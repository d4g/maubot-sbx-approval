"""The logic of sbx-approval without maubot: request and response signing, and the open questions.

Kept free of maubot and mautrix imports so it can be tested on its own (tests/test_core.py).

Signing. The caller and the plugin share a secret that never crosses the wire. Every request carries
    X-Sbx-Time   Unix time in seconds
    X-Sbx-Nonce  16 to 64 characters [A-Za-z0-9_-], never reused
    X-Sbx-Mac    hex HMAC-SHA256 over request_message(...)
and every signed response carries X-Sbx-Mac over response_message(...), bound to the request's nonce, so a man in the
middle can neither forge an answer nor replay an old one. The plugin refuses a request older or newer than MAX_SKEW
seconds, or with a nonce it has seen.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from dataclasses import dataclass, field

MAX_SKEW = 60
SECRET_MIN = 32
NONCE = re.compile(r"[A-Za-z0-9_-]{16,64}")
QID = re.compile(r"[A-Za-z0-9_-]{1,64}")
TOKEN = re.compile(r"[A-Za-z0-9_-]{16,128}")
TEXT_MAX = 2000
LABEL_MAX = 40
ANSWERS_MIN, ANSWERS_MAX = 2, 8
TIMEOUT_MIN, TIMEOUT_MAX = 30, 3600
OPEN_MAX = 50
KEEP_DONE = 3600
# The detail (a diff) goes into the thread message twice (body and formatted_body), and the encrypted event must stay
# under Matrix's 65536 bytes (spec, "Size limits") after base64. THREAD_EVENT_MAX bounds the plaintext content.
DETAIL_MAX = 16 * 1024
THREAD_EVENT_MAX = 40 * 1024
# The code the approver types for a strict question: lowercase letters and digits, easy on a phone keyboard, without
# the look-alikes 0/o and 1/l. 32^6 is about 10^9 for one attempt.
CODE_ALPHABET = "abcdefghijkmnpqrstuvwxyz23456789"
CODE_LEN = 6

POLL_START = "org.matrix.msc3381.poll.start"
POLL_RESPONSE = "org.matrix.msc3381.poll.response"
POLL_END = "org.matrix.msc3381.poll.end"
POLL_DISCLOSED = "org.matrix.msc3381.poll.disclosed"
TEXT = "org.matrix.msc1767.text"


class Refused(Exception):
    """A request the plugin will not act on; the message is safe to return to the caller."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def request_message(method: str, path: str, ts: str, nonce: str, body: bytes) -> bytes:
    return "\n".join(["sbx-approval-request", method.upper(), path, ts, nonce, _sha256(body)]).encode()


def response_message(nonce: str, status: int, body: bytes) -> bytes:
    return "\n".join(["sbx-approval-response", nonce, str(status), _sha256(body)]).encode()


def mac(secret: bytes, message: bytes) -> str:
    return hmac.new(secret, message, hashlib.sha256).hexdigest()


def sign_request(secret: bytes, method: str, path: str, body: bytes, now: float | None = None) -> dict[str, str]:
    """The headers a caller sends. Used by the tests; the caller in sbx implements the same."""
    ts = str(int(time.time() if now is None else now))
    nonce = secrets.token_urlsafe(24)
    return {"X-Sbx-Time": ts, "X-Sbx-Nonce": nonce,
            "X-Sbx-Mac": mac(secret, request_message(method, path, ts, nonce, body))}


class Nonces:
    """Nonces seen in the last 2 * MAX_SKEW seconds; older ones are refused by the time check anyway."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}

    def use(self, nonce: str, now: float) -> bool:
        self.prune(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = now
        return True

    def prune(self, now: float) -> None:
        limit = now - 2 * MAX_SKEW
        for key in [k for k, t in self._seen.items() if t < limit]:
            del self._seen[key]


def check_request(secret: bytes | None, nonces: Nonces, method: str, path: str, headers, body: bytes,
                  now: float) -> str:
    """Return the request's nonce if it is signed correctly and fresh; raise Refused otherwise."""
    if secret is None:
        raise Refused(503, "no secret configured")
    ts, nonce, given = headers.get("X-Sbx-Time", ""), headers.get("X-Sbx-Nonce", ""), headers.get("X-Sbx-Mac", "")
    if not ts.isdigit() or not NONCE.fullmatch(nonce) or not given:
        raise Refused(401, "unsigned")
    if not hmac.compare_digest(mac(secret, request_message(method, path, ts, nonce, body)), given):
        raise Refused(401, "bad signature")
    if abs(now - int(ts)) > MAX_SKEW:
        raise Refused(401, "stale")
    if not nonces.use(nonce, now):
        raise Refused(401, "replayed")
    return nonce


def check_response(secret: bytes, nonce: str, status: int, body: bytes, given: str) -> bool:
    """What the caller checks before it trusts an answer."""
    return hmac.compare_digest(mac(secret, response_message(nonce, status, body)), given or "")


@dataclass
class Answer:
    id: str
    label: str
    token: str


def make_code() -> str:
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LEN))


@dataclass
class Question:
    qid: str
    text: str
    answers: list[Answer]
    expires: float
    detail: str | None = None
    # Strict: approval only by typing the code in the poll's thread; the poll offers only the refusal.
    code: str | None = None
    code_token: str | None = None
    code_label: str | None = None
    event_id: str | None = None
    state: str = "open"  # open, answered, expired, closed
    token: str | None = None
    label: str | None = None
    done_at: float | None = None


@dataclass
class Questions:
    """Open and recently finished questions, in memory: a restart of maubot forgets them, and the caller then gets
    'unknown' and keeps waiting on its other channel."""

    items: dict[str, Question] = field(default_factory=dict)
    by_event: dict[str, str] = field(default_factory=dict)

    def add(self, data, default_timeout: int, now: float) -> Question:
        if not isinstance(data, dict):
            raise Refused(400, "body must be a JSON object")
        qid, text, answers = data.get("id"), data.get("question"), data.get("answers")
        timeout = data.get("timeout", default_timeout)
        if not isinstance(qid, str) or not QID.fullmatch(qid):
            raise Refused(400, "bad id")
        if qid in self.items:
            raise Refused(409, "id already used")
        if not isinstance(text, str) or not 1 <= len(text) <= TEXT_MAX:
            raise Refused(400, "bad question")
        detail, strict = data.get("detail"), data.get("strict")
        if detail is not None:
            if not isinstance(detail, str) or not detail.strip():
                raise Refused(400, "bad detail")
            if len(detail.encode()) > DETAIL_MAX:
                raise Refused(413, "detail too long")
        strict_label = None
        if strict is not None:
            if not isinstance(strict, dict) or not isinstance(strict.get("token"), str) \
                    or not TOKEN.fullmatch(strict["token"]):
                raise Refused(400, "bad strict")
            strict_label = strict.get("label", "Freigegeben")
            if not isinstance(strict_label, str) or not 1 <= len(strict_label) <= LABEL_MAX:
                raise Refused(400, "bad strict label")
        least = 1 if strict is not None else ANSWERS_MIN
        if not isinstance(answers, list) or not least <= len(answers) <= ANSWERS_MAX:
            raise Refused(400, f"need {least} to {ANSWERS_MAX} answers")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not TIMEOUT_MIN <= timeout <= TIMEOUT_MAX:
            raise Refused(400, "bad timeout")
        if sum(1 for q in self.items.values() if q.state == "open") >= OPEN_MAX:
            raise Refused(429, "too many open questions")
        parsed, labels = [], set()
        tokens = {strict["token"]} if strict is not None else set()
        for item in answers:
            label = item.get("label") if isinstance(item, dict) else None
            token = item.get("token") if isinstance(item, dict) else None
            if not isinstance(label, str) or not 1 <= len(label) <= LABEL_MAX or label in labels:
                raise Refused(400, "bad or repeated answer label")
            if not isinstance(token, str) or not TOKEN.fullmatch(token) or token in tokens:
                raise Refused(400, "bad or repeated answer token")
            labels.add(label)
            tokens.add(token)
            # The poll's answer ids go to Matrix; the tokens never do.
            parsed.append(Answer(id=secrets.token_urlsafe(9), label=label, token=token))
        question = Question(qid=qid, text=text, answers=parsed, expires=now + timeout, detail=detail)
        if strict is not None:
            question.code, question.code_token, question.code_label = make_code(), strict["token"], strict_label
        if question.code or question.detail:
            # Measured with a placeholder as long as any event id, because the check must come before the poll is sent.
            size = len(json.dumps(thread_content(question, "$" + "x" * 64)).encode())
            if size > THREAD_EVENT_MAX:
                raise Refused(413, "detail too long for one Matrix event")
        self.items[qid] = question
        return question

    def bind(self, question: Question, event_id: str) -> None:
        question.event_id = event_id
        self.by_event[event_id] = question.qid

    def drop(self, question: Question) -> None:
        """Forget a question whose poll could not be sent."""
        self.items.pop(question.qid, None)

    def vote(self, event_id: str | None, sender: str, answer_ids, approver: str, now: float) -> Question | None:
        """Count the first vote of the approver on an open question; everything else changes nothing."""
        question = self.items.get(self.by_event.get(event_id or "", ""))
        if question is None or question.state != "open" or sender != approver:
            return None
        if now >= question.expires or not isinstance(answer_ids, list) or not answer_ids:
            return None
        chosen = next((a for a in question.answers if a.id == answer_ids[0]), None)
        if chosen is None:
            return None
        question.state, question.token, question.label, question.done_at = "answered", chosen.token, chosen.label, now
        return question

    def code_wait(self, root: str | None, now: float) -> str:
        """Why a thread message under <root> cannot answer anything, or "" if a strict question waits for its code.
        Only for the log and to skip fetching the event; code_reply decides."""
        question = self.items.get(self.by_event.get(root or "", ""))
        if question is None:
            return "no question for that thread"
        if question.code is None:
            return f"question {question.qid} is not strict"
        if question.state != "open":
            return f"question {question.qid} is {question.state}"
        if now >= question.expires:
            return f"question {question.qid} has expired"
        return ""

    def code_reply(self, root: str | None, sender: str, text: str, approver: str,
                   now: float) -> tuple[Question, bool] | None:
        """A message of the approver in the thread of an open strict question: the one attempt. The right code answers
        with the strict token; anything else is the refusal, so a wrong guess cannot be followed by a second one."""
        question = self.items.get(self.by_event.get(root or "", ""))
        if question is None or question.code is None or question.state != "open" or sender != approver:
            return None
        if now >= question.expires:
            return None
        ok = hmac.compare_digest(normalize_code(text).encode(), question.code.encode())
        chosen_token, chosen_label = (question.code_token, question.code_label) if ok \
            else (question.answers[0].token, question.answers[0].label)
        question.state, question.token, question.label, question.done_at = "answered", chosen_token, chosen_label, now
        return question, ok

    def close(self, qid: str, label: str | None, now: float) -> Question | None:
        """The caller got its answer on another channel: end the poll without a token."""
        question = self.items.get(qid)
        if question is None or question.state != "open":
            return None
        question.state, question.label, question.done_at = "closed", label, now
        return question

    def expire(self, now: float) -> list[Question]:
        ended = []
        for question in self.items.values():
            if question.state == "open" and now >= question.expires:
                question.state, question.done_at = "expired", now
                ended.append(question)
        return ended

    def prune(self, now: float) -> None:
        for qid in [k for k, q in self.items.items() if q.done_at is not None and now - q.done_at > KEEP_DONE]:
            question = self.items.pop(qid)
            self.by_event.pop(question.event_id or "", None)

    def answer(self, qid: str) -> dict:
        question = self.items.get(qid)
        if question is None:
            raise Refused(404, "unknown")
        if question.state == "answered":
            return {"state": "answered", "token": question.token}
        return {"state": question.state}


STRICT_HINT = "Freigeben nur mit dem Code im Thread."


def poll_text(question: Question) -> str:
    return f"{question.text}\n{STRICT_HINT}" if question.code else question.text


def poll_start_content(question: Question) -> dict:
    text = poll_text(question)
    fallback = text + "\n" + "\n".join(f"{n}. {a.label}" for n, a in enumerate(question.answers, 1))
    return {
        POLL_START: {
            "question": {TEXT: text, "body": text, "msgtype": "m.text"},
            "kind": POLL_DISCLOSED,
            "max_selections": 1,
            "answers": [{"id": a.id, TEXT: a.label} for a in question.answers],
        },
        TEXT: fallback,
        "body": fallback,
    }


def normalize_code(text: str) -> str:
    """The last line that is not a quoted reply fallback, without blanks, lowercased: a phone capitalises the first
    letter, and some clients still quote the replied-to message."""
    lines = [line.strip() for line in (text or "").splitlines() if line.strip() and not line.lstrip().startswith(">")]
    return "".join(lines[-1].split()).lower() if lines else ""


def html_escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _in_thread(root: str) -> dict:
    return {"rel_type": "m.thread", "event_id": root, "is_falling_back": True, "m.in_reply_to": {"event_id": root}}


def thread_content(question: Question, root: str) -> dict:
    """The message in the poll's thread: the detail as a code block, and for a strict question the code to type,
    after the detail, so it is seen only by scrolling past it."""
    body, html = [], []
    if question.detail:
        body.append(question.detail)
        html.append(f"<pre><code>{html_escape(question.detail)}</code></pre>")
    if question.code:
        hint = "Eine andere Antwort hier gilt als Ablehnen. Es gibt nur einen Versuch."
        body.append(f"Freigeben: antworte in diesem Thread mit {question.code}\n{hint}")
        html.append(f"<p>Freigeben: antworte in diesem Thread mit <code>{question.code}</code><br>{hint}</p>")
    return {"msgtype": "m.text", "body": "\n\n".join(body), "format": "org.matrix.custom.html",
            "formatted_body": "".join(html), "m.relates_to": _in_thread(root)}


def thread_note(root: str, text: str) -> dict:
    return {"msgtype": "m.notice", "body": text, "m.relates_to": _in_thread(root)}


def thread_root(content: dict) -> str | None:
    """The thread a message belongs to, or None."""
    relates = content.get("m.relates_to") or {}
    if not isinstance(relates, dict) or relates.get("rel_type") != "m.thread":
        return None
    root = relates.get("event_id")
    return root if isinstance(root, str) else None


def poll_end_content(event_id: str, text: str) -> dict:
    return {
        "m.relates_to": {"rel_type": "m.reference", "event_id": event_id},
        POLL_END: {},
        TEXT: text,
        "body": text,
    }


def response_answers(content: dict) -> tuple[str | None, list]:
    """The poll event a response refers to, and the chosen answer ids."""
    relates = content.get("m.relates_to") or {}
    if not isinstance(relates, dict) or relates.get("rel_type") != "m.reference":
        return None, []
    response = content.get(POLL_RESPONSE) or {}
    answers = response.get("answers") if isinstance(response, dict) else None
    return relates.get("event_id"), answers if isinstance(answers, list) else []


URL = re.compile(r"https?://[^\s<>\"']{1,2000}")


def link_text(data) -> tuple[str, str]:
    if not isinstance(data, dict):
        raise Refused(400, "body must be a JSON object")
    text, url = data.get("text"), data.get("url")
    if not isinstance(text, str) or not 1 <= len(text) <= 500:
        raise Refused(400, "bad text")
    if not isinstance(url, str) or not URL.fullmatch(url):
        raise Refused(400, "bad url")
    return text, url
