#!/usr/bin/env python3
"""Reference client for sbx-approval, standard library only. Asks one question and waits for the answer.

    SBX_SECRET=... python3 examples/client.py http://<maubot>:29316/_matrix/maubot/plugin/<instance> "Question?"

The secret comes from the environment so it stays out of the process list and the shell history. Prints each
state it sees, and the chosen answer's label; exits 0 when answered, 1 when expired, closed or on any error.
"""
import hashlib
import hmac
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.request


def call(base: str, secret: bytes, method: str, path: str, data=None) -> tuple[int, dict]:
    body = json.dumps(data).encode() if data is not None else b""
    url = base.rstrip("/") + path
    # Signed is the path below the instance (e.g. /answer/q1): maubot strips its prefix before the plugin sees it.
    ts, nonce = str(int(time.time())), secrets.token_urlsafe(24)
    message = "\n".join(["sbx-approval-request", method, path, ts, nonce, hashlib.sha256(body).hexdigest()])
    request = urllib.request.Request(url, data=body if method != "GET" else None, method=method, headers={
        "Content-Type": "application/json", "X-Sbx-Time": ts, "X-Sbx-Nonce": nonce,
        "X-Sbx-Mac": hmac.new(secret, message.encode(), hashlib.sha256).hexdigest()})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, raw, given = response.status, response.read(), response.headers.get("X-Sbx-Mac", "")
    except urllib.error.HTTPError as error:
        status, raw, given = error.code, error.read(), error.headers.get("X-Sbx-Mac", "")
    expected = hmac.new(secret, "\n".join(["sbx-approval-response", nonce, str(status),
                                           hashlib.sha256(raw).hexdigest()]).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, given):
        raise SystemExit(f"unsigned or wrongly signed answer, HTTP {status}: {raw[:200]!r}")
    return status, json.loads(raw)


def main() -> int:
    if len(sys.argv) != 3 or not os.environ.get("SBX_SECRET"):
        print(__doc__, file=sys.stderr)
        return 2
    base, question = sys.argv[1], sys.argv[2]
    secret = os.environ["SBX_SECRET"].encode()
    labels = ["Ablehnen", "Einmal", "10 Minuten"]
    tokens = {secrets.token_urlsafe(24): label for label in labels}
    qid = "try-" + secrets.token_hex(4)
    status, answer = call(base, secret, "POST", "/ask", {
        "id": qid, "question": question, "timeout": 120,
        "answers": [{"label": label, "token": token} for token, label in tokens.items()]})
    print("ask:", status, answer)
    if status != 201:
        return 1
    last = None
    while True:
        status, answer = call(base, secret, "GET", f"/answer/{qid}")
        if answer != last:
            print("answer:", status, {k: v for k, v in answer.items() if k != "token"})
            last = answer
        if answer.get("state") == "answered":
            label = tokens.get(answer.get("token"))
            print("chosen:", label if label else "TOKEN DOES NOT MATCH ANY ANSWER")
            return 0 if label else 1
        if answer.get("state") != "open":
            return 1
        time.sleep(2)


if __name__ == "__main__":
    sys.exit(main())
