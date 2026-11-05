"""A fake requests session, so the download tests never touch the internet."""

import json


class FakeResponse:
    def __init__(self, status: int = 200, body: bytes = b""):
        self.status_code = status
        self.content = body

    @property
    def text(self) -> str:
        return self.content.decode("utf-8")

    def json(self):
        return json.loads(self.content)


class FakeSession:
    """Answers each URL from a list of canned responses, in order."""

    def __init__(self, answers: dict[str, list]):
        self.answers = {url: list(items) for url, items in answers.items()}
        self.asked: list[str] = []

    def get(self, url, timeout=None):
        self.asked.append(url)
        answer = self.answers[url].pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer
