# Model card: the DingDongDitch risk model

What the model is, how it is tested, what the tests show and where it is weak.

## What it is for

It ranks CVEs by how likely attackers are to use them, so that a service with dozens of known CVEs gets a short list of the ones to fix first. A scan uses it to give each CVE a level and a "riskier than X% of CVEs" figure.

It is not a measure of how bad a CVE is if exploited (that is CVSS), and not a probability. Only the order of its scores is used.

Don't use it as the only reason to leave something unpatched. It has been tested on which CVEs CISA went on to list, not on your network.

## Data

All four sources are free and public. `dingdongditch update-db` downloads them.

| Source | Used for |
|---|---|
| [NVD](https://nvd.nist.gov/) | Each CVE's description, CVSS, weakness type, and affected products |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | The answer key: a CVE on the list counts as exploited |
| [Exploit-DB](https://www.exploit-db.com/) | Whether a public exploit exists, and what kind |
| [EPSS](https://www.first.org/epss/) | Never an input. It is the ranking the model is compared with |

## What it looks at

- The CVSS score and each part of the vector. One set of clues for every CVE: v3 where NVD has it, otherwise v2 translated into v3's terms.
- Weakness types (CWE).
- The vendors and products the CVE affects.
- Words and word pairs in the description.
- Public exploits on Exploit-DB: how many, verified or not, remote, web or local.
- How long the CVE has been public.

NVD's references are left out on purpose. Links to news stories and exploits pile up after an attack, so they would leak the answer.

## How it is built

A logistic regression (C=0.3) by default: it adds up clues, trains in about 2 minutes, and each clue's weight can be read straight off it, which is where a scan's "Why" line comes from. `train --xgboost` trains XGBoost instead.

It trains on every CVE public on the training day. CVEs already on CISA's list count as exploited, and everything else as not yet.

## How it is tested

`dingdongditch train --test DAY` is a time-travel test:

1. Stand on a past day. Train on only what was known then: the CVEs public by then, CISA's list as it stood, the exploits Exploit-DB had published.
2. Rank every CVE that was public and not yet on CISA's list.
3. Look at which of them CISA listed in the following year. A good ranking has them near the top.

The measures are the share of those listed CVEs caught by fixing the top 1%, 5% or 10% of the ranking, and average precision. The baselines are CVSS, "has a public exploit", and EPSS as it was on that day. Today's EPSS already knows what happened next, and using it would roughly double EPSS's numbers.

Since release 0.1.0 the test also prints:

- **A 95% interval for every number.** A test year has few listed CVEs: 91 and 53 in the two tests below. The listed CVEs are redrawn 2,000 times, each time as many as there were, with repeats, and the interval covers the middle 95% of the results. The other CVEs, 200,000 or more, are kept as they are: they only decide where the top of a ranking ends.
- **The model against EPSS, CVE by CVE.** On the same listed CVEs: the gap between the two with its interval, how many CVEs only one of them caught, and a sign test on those. The model is called ahead "beyond chance" only where the interval stays above 0 and the p-value is under 0.05.
- **A giveaway check.** NVD keeps no history, so a description read today may say "exploited in the wild" because someone added it after the attack. The whole test is repeated without every CVE whose description says so.
- **Several years added up.** Give `--test` more than once, a year or more apart, and every listed CVE of every year is judged in its own year and counted in one table.

`--tune` takes one more choice out of the test. Without it, the model uses built-in settings. With it, the settings for each test day are chosen by standing a year before that day and judging on the year up to it, so nothing after the test day has any say in how the model is built.

To run all of it:

```bash
dingdongditch update-db --epss-date 2022-05-01 --epss-date 2023-05-01 --epss-date 2024-05-01 --epss-date 2025-05-01
dingdongditch train --test 2022-05-01 --test 2023-05-01 --test 2024-05-01 --test 2025-05-01 --tune
```

Two things to know when reading that output:

- CISA's list began in November 2021. A year before 1 May 2022 it didn't exist, so that day can't be tuned and falls back to the built-in settings. The command says so.
- The built-in settings were chosen on the year after 1 May 2024. Without `--tune`, that year's numbers flatter the model.

## Results so far

From release 0.1.0, with the built-in settings. The numbers in brackets are CVEs caught.

**From 1 May 2025:** 275,380 CVEs ranked, 91 of them listed by CISA in the next year.

| Ranking | Top 1% | Top 5% | Top 10% | Average precision |
|---|---|---|---|---|
| CVSS | 1.6% | 14.6% | 31.1% | 0.0008 |
| Has a public exploit | 2.0% | 10.0% | 18.7% | 0.0004 |
| EPSS as it was that day | 27.5% (25) | 52.7% (48) | 58.2% (53) | 0.0332 |
| **DingDongDitch** | **31.9% (29)** | **54.9% (50)** | **73.6% (67)** | **0.0597** |

**From 1 May 2023:** 200,343 CVEs ranked, 53 of them listed by CISA in the next year.

| Ranking | Top 1% | Top 5% | Top 10% | Average precision |
|---|---|---|---|---|
| CVSS | 0.0% | 9.9% | 33.4% | 0.0007 |
| Has a public exploit | 2.5% | 12.6% | 25.3% | 0.0004 |
| EPSS as it was that day | 24.5% (13) | 32.1% (17) | 37.7% (20) | 0.0122 |
| **DingDongDitch** | **34.0% (18)** | **54.7% (29)** | **77.4% (41)** | **0.0218** |

These two tables were made before the test printed intervals. What the counts alone can settle, with a sign test on the CVEs only one ranking caught:

| Comparison with EPSS | Lead | Can it be luck? |
|---|---|---|
| Top 1%, 2025 | 29 against 25 | Yes. A lead of 4 CVEs gives p = 0.125 at best |
| Top 1%, 2023 | 18 against 13 | Yes. A lead of 5 CVEs gives p = 0.06 at best |
| Top 5%, 2025 | 50 against 48 | Yes |
| Top 5%, 2023 | 29 against 17 | Depends on how the catches overlap: p is anywhere from under 0.001 to about 0.10 |
| Top 10%, 2025 | 67 against 53 | Depends on how the catches overlap: p is anywhere from under 0.001 to about 0.10 |
| Top 10%, 2023 | 41 against 20 | No. p is under 0.01 however they overlap |

"At best" means: if the extra CVEs were the only ones the two rankings disagreed on. The tests on `main` print the real overlap, so the two "depends" rows get an answer when the four-year test is run.

So the claim these results support is: far better than CVSS, at least as good as EPSS at the very top, and better than EPSS in the top 10%.

## What it learned

Products from Cisco, Ivanti, Microsoft, SonicWall and Citrix raise a score, and so do vendor notes like "exploited in the wild" or "Apple is aware of a report". CVEs NVD hasn't scored yet, and bug types like null-pointer crashes, lower it.

## Where it is weak

- **Small test years.** 91 and 53 listed CVEs. One or two catches move the top-1% number by a few points.
- **Descriptions are today's copies.** NVD keeps no history, so CVSS, descriptions and products are read as they are now. They rarely change once a CVE is analysed, but in the 2025 test 10 of the 91 listed CVEs say "exploited in the wild" in their description. All 10 were published before the test day, 8 of them in 2008 to 2013, when NVD descriptions routinely said so. Without them, the model ties EPSS in the top 1% and 5% and still leads in the top 10% (70.4% against 55.6%). The giveaway check now does this in every test. It drops those CVEs from the judging. The model is still trained on those words.
- **The default was chosen after seeing the test years.** XGBoost and logistic regression tied across the two test years (XGBoost a little better from 2025, logistic regression from 2023), and logistic regression became the default after seeing that. `--tune` removes this from a test.
- **Three cut-offs, several years.** Each test compares the model with EPSS at 1%, 5% and 10%. One p-value under 0.05 among several is weaker than it looks, so look for the same result in more than one year.
- **CISA's list is the only answer key.** It holds exploitation CISA has confirmed, so some CVEs counted as "not exploited" really were. This makes every ranking look a little worse, the same for all of them.
- **Old CVEs are ranked too low.** CISA's list rarely includes old CVEs. Of the CVEs from before 2012 that have a public remote exploit, 0.7% are on it, against 16.5% for CVEs since 2018. The model learns that, so it ranks an old CVE low even when it is dangerous on a server that never got patched. A scan makes up for it with a rule: a public remote exploit on Exploit-DB always means at least `HIGH`.
- **Nothing can rank a CVE before it is public.** In the year after 1 May 2025, CISA listed 259 CVEs, and 168 of them were brand new, mostly zero-days. Those aren't in the test.
- **Vendor names carry weight.** A product from a vendor attackers favour scores higher. That is a real pattern, and it also means a product from a vendor the model has rarely seen gets no such boost.
