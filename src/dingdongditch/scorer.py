"""Score the CVEs a scan found, and explain each score in plain words.

Each CVE gets a level:
  KNOWN EXPLOITED  CISA already lists it as used in real attacks
  HIGH             the model ranks it in the top 1% of all CVEs, or Exploit-DB has a
                   public remote exploit for it (a rule, not the model: see below)
  MEDIUM           top 5%
  LOW              everything else

plus the clues that raised its score most (the "why") and, where NVD says, the
first release that fixes it.

Why the rule: the model learns from CISA's list, which tracks current attack
campaigns and rarely includes old CVEs (0.7% of pre-2012 CVEs with a public remote
exploit, against 16.5% since 2018). So it ranks a 2007 bug low, even though anyone
can run that exploit against a server that was never patched.
"""

from __future__ import annotations

import bisect
import sqlite3
from dataclasses import dataclass, field, replace
from datetime import date, timedelta
from pathlib import Path

import pandas as pd
from scipy import sparse

from dingdongditch import db, features
from dingdongditch.matcher import Match, match_service
from dingdongditch.nmap_parser import Service
from dingdongditch.train import load_saved

LEVELS = ("KNOWN EXPLOITED", "HIGH", "MEDIUM", "LOW")  # worst first
HIGH_SHARE = 0.99  # riskier than 99% of all CVEs
MEDIUM_SHARE = 0.95
REASONS = 3

_CWE_NAMES = {
    "CWE-20": "poor input checking",
    "CWE-22": "path traversal",
    "CWE-77": "command injection",
    "CWE-78": "OS command injection",
    "CWE-79": "cross-site scripting",
    "CWE-89": "SQL injection",
    "CWE-94": "code injection",
    "CWE-119": "memory corruption",
    "CWE-120": "buffer overflow",
    "CWE-121": "stack buffer overflow",
    "CWE-122": "heap buffer overflow",
    "CWE-287": "broken authentication",
    "CWE-288": "authentication bypass",
    "CWE-290": "authentication bypass by spoofing",
    "CWE-306": "missing authentication",
    "CWE-416": "use after free",
    "CWE-434": "unrestricted file upload",
    "CWE-502": "unsafe deserialization",
    "CWE-787": "out-of-bounds write",
    "CWE-798": "hard-coded credentials",
    "CWE-843": "type confusion",
    "CWE-918": "server-side request forgery",
}
_CVSS_PARTS = {  # in v3 terms: features.py translates v2 vectors
    "AV": {"N": "reachable over the network", "A": "reachable from the same network"},
    "AC": {"L": "easy to pull off"},
    "PR": {"N": "no login needed"},
    "UI": {"N": "no user action needed"},
    "S": {"C": "can reach beyond the service"},
    "C": {"H": "can expose all data"},
    "I": {"H": "can change any data"},
    "A": {"H": "can take the service down"},
}
# Number features are centred on the average CVE, so only an above-average value
# is described; "less than average" is not a reason worth printing.
_NUMBERS = {
    "cvss_score": "high CVSS score",
    "log_exploits": "public exploit on Exploit-DB",
    "exploit_verified": "verified exploit on Exploit-DB",
    "exploit_remote": "remote exploit on Exploit-DB",
    "exploit_webapps": "web exploit on Exploit-DB",
    "exploit_local": "local exploit on Exploit-DB",
    "log_age_days": "public for a long time",
    "no_cvss": "no CVSS score yet",
}


class ModelError(Exception):
    """The database or model needed for risk scores is missing or unusable."""


@dataclass(frozen=True)
class ScoredCVE:
    cve_id: str
    level: str
    riskier_than: float  # share of all CVEs the model scores lower, 0 to 1
    certain: bool  # False: only some of the releases the service could be are affected
    fixed_in: str | None
    cvss: float | None
    epss: float | None  # today's EPSS, for reference
    summary: str  # the start of NVD's description
    reasons: list[str] = field(default_factory=list)  # the model's top clues
    rule: str | None = None  # set when a rule, not the model, raised the level
    last_affected: str | None = None  # when NVD names no fix: the last affected release


def describe(name: str, value: float) -> str | None:
    """A model feature name like 'cvss3__PR=N' as words, or None if not worth saying."""
    group, _, item = name.partition("__")
    if group == "number":
        return _NUMBERS.get(item) if value > 0 else None
    if value <= 0:
        return None
    if group == "cvss":
        key, _, level = item.partition("=")
        return _CVSS_PARTS.get(key, {}).get(level)
    if group == "cwe":
        return f"{_CWE_NAMES[item]} ({item})" if item in _CWE_NAMES else f"weakness {item}"
    if group == "product":  # NVD lists every product a CVE affects, not just the scanned one
        vendor, _, product = item.partition(":")
        return f"affects {product} ({vendor})" if product else f"affects {vendor} products"
    if group == "text":
        return f'description says "{item}"'
    return None


_EXPLOIT_DB = "on Exploit-DB"
REMOTE_EXPLOIT_RULE = "public remote exploit on Exploit-DB, so at least HIGH"


def level_for(listed_by_cisa: bool, riskier_than: float, remote_exploit: bool = False) -> str:
    if listed_by_cisa:
        return "KNOWN EXPLOITED"
    if riskier_than >= HIGH_SHARE or remote_exploit:
        return "HIGH"
    if riskier_than >= MEDIUM_SHARE:
        return "MEDIUM"
    return "LOW"


def worst(scored: list[ScoredCVE]) -> str | None:
    """The most serious level among a service's CVEs."""
    return min((s.level for s in scored), key=LEVELS.index, default=None)


def _worst_first(s: ScoredCVE) -> tuple:
    return LEVELS.index(s.level), -s.riskier_than, s.cve_id


_NO_NEWS = ("an issue was discovered in", "a vulnerability was found in")


def _summary(description: str, limit: int = 110) -> str:
    sentences = [s.strip() for s in description.split(". ") if s.strip()] or [""]
    first = sentences[0]
    if len(sentences) > 1 and first.lower().startswith(_NO_NEWS):  # says nothing yet
        first = sentences[1]
    return first if len(first) <= limit else first[: limit - 3].rstrip() + "..."


def _contributions(classifier, matrix) -> sparse.csr_matrix:
    """How much each feature pushed each CVE's score up or down."""
    if hasattr(classifier, "coef_"):  # logistic regression: weight times value
        return sparse.csr_matrix(matrix).multiply(classifier.coef_[0]).tocsr()
    from xgboost import DMatrix  # XGBoost works out the same thing itself

    booster = classifier.get_booster()
    return sparse.csr_matrix(booster.predict(DMatrix(matrix), pred_contribs=True)[:, :-1])


class Scorer:
    def __init__(self, con: sqlite3.Connection, saved: dict):
        if "spread" not in saved:
            raise ModelError(
                "The model file was made by an older version. Run `dingdongditch train` again."
            )
        self.con = con
        self.pipeline = saved["model"]
        self.spread = saved["spread"]

    @classmethod
    def open(cls, db_path: Path, model_path: Path) -> Scorer:
        if not db_path.exists():
            raise ModelError(
                f"No vulnerability database at {db_path}: run `dingdongditch update-db`."
            )
        if not model_path.exists():
            raise ModelError(
                f"No model at {model_path}: run `dingdongditch update-db` or `dingdongditch train`."
            )
        try:
            con = db.connect(db_path)
        except db.DatabaseError as exc:
            raise ModelError(str(exc)) from exc
        try:
            return cls(con, load_saved(model_path))
        except ModelError:
            con.close()
            raise
        except Exception as exc:  # a damaged or foreign file can fail in many ways
            con.close()
            raise ModelError(f"Can't read the model at {model_path}: {exc}") from exc

    def close(self) -> None:
        self.con.close()

    def score_services(self, services: list[Service]) -> list[list[ScoredCVE]]:
        """Each service's CVEs, scored and worst first.

        A CVE found on several ports is scored once: only whether it surely applies
        and which release fixes it differ from port to port.
        """
        found = [match_service(self.con, svc) for svc in services]
        unique = {m.cve_id: m for matches in found for m in matches}
        scored = {s.cve_id: s for s in self.score(list(unique.values()))}
        return [
            sorted(
                (
                    replace(
                        scored[m.cve_id], certain=m.certain, fixed_in=m.fixed_in,
                        last_affected=m.last_affected,
                    )
                    for m in matches
                    if m.cve_id in scored
                ),
                key=_worst_first,
            )
            for matches in found
        ]

    def riskier_than(self, score: float) -> float:
        return bisect.bisect_left(self.spread, score) / (len(self.spread) - 1)

    def score(self, matches: list[Match]) -> list[ScoredCVE]:
        """Score and explain matched CVEs, worst first."""
        if not matches:
            return []
        found = {m.cve_id: m for m in matches}
        frame = features.load(self.con, date.today() + timedelta(days=1), ids=list(found))
        if frame.empty:
            return []
        ids = list(frame["id"])
        marks = ", ".join("?" * len(ids))
        epss = dict(
            self.con.execute(f"SELECT cve_id, score FROM epss WHERE cve_id IN ({marks})", ids)
        )
        vectorizer = self.pipeline.named_steps["features"]
        classifier = self.pipeline.named_steps["classifier"]
        matrix = sparse.csr_matrix(vectorizer.transform(frame))
        chances = classifier.predict_proba(matrix)[:, 1]
        pushes = _contributions(classifier, matrix)
        names = vectorizer.get_feature_names_out()

        results = []
        for row, item in enumerate(frame.itertuples(index=False)):
            match = found[item.id]
            share = self.riskier_than(chances[row])
            push = pushes.getrow(row)
            order = push.data.argsort()[::-1]
            reasons: list[str] = []
            vendors: set[str] = set()  # one reason per vendor, not one per product
            for amount, index in zip(push.data[order], push.indices[order], strict=True):
                if amount <= 0 or len(reasons) == REASONS:
                    break
                group, _, item_name = names[index].partition("__")
                vendor = item_name.partition(":")[0] if group == "product" else None
                words = describe(names[index], matrix[row, index])
                if words and words.endswith(_EXPLOIT_DB):  # one Exploit-DB clue is enough
                    vendor = _EXPLOIT_DB
                if vendor in vendors:
                    continue
                if words and words not in reasons:
                    reasons.append(words)
                    if vendor:
                        vendors.add(vendor)
            cvss = item.cvss3_score if pd.notna(item.cvss3_score) else item.cvss2_score
            listed, remote = isinstance(item.kev_added, str), item.exploit_remote > 0
            level = level_for(listed, share, remote)
            raised = level != level_for(listed, share)
            results.append(
                ScoredCVE(
                    cve_id=item.id,
                    level=level,
                    riskier_than=share,
                    certain=match.certain,
                    fixed_in=match.fixed_in,
                    last_affected=match.last_affected,
                    cvss=float(cvss) if pd.notna(cvss) else None,
                    epss=epss.get(item.id),
                    summary=_summary(item.description),
                    reasons=reasons,
                    rule=REMOTE_EXPLOIT_RULE if raised else None,
                )
            )
        return sorted(results, key=_worst_first)
