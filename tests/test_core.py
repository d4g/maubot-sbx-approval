import json
import pathlib
import sys

import pytest

# core.py on its own: the package's __init__ needs maubot, which these tests do not.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "sbx_approval"))
import core  # noqa: E402

SECRET = b"s" * 40
T0 = 1_800_000_000.0
APPROVER = "@dag:example.org"


def ask(qs, qid="q1", timeout=None, now=T0):
    data = {"id": qid, "question": "Darf ha-call light.turn_on laufen?",
            "answers": [{"label": "Ablehnen", "token": "a" * 20}, {"label": "Einmal", "token": "b" * 20},
                        {"label": "10 Minuten", "token": "c" * 20}]}
    if timeout is not None:
        data["timeout"] = timeout
    return qs.add(data, 900, now)


# --- signing -----------------------------------------------------------------------------------------------------

def test_signed_request_passes_once():
    body = b'{"x":1}'
    headers = core.sign_request(SECRET, "POST", "/p/ask", body, now=T0)
    nonces = core.Nonces()
    assert core.check_request(SECRET, nonces, "POST", "/p/ask", headers, body, T0 + 5) == headers["X-Sbx-Nonce"]
    with pytest.raises(core.Refused, match="replayed"):
        core.check_request(SECRET, nonces, "POST", "/p/ask", headers, body, T0 + 6)


@pytest.mark.parametrize("change", ["body", "path", "method", "secret"])
def test_any_change_breaks_the_signature(change):
    body = b'{"x":1}'
    headers = core.sign_request(SECRET, "POST", "/p/ask", body, now=T0)
    args = {"secret": SECRET, "method": "POST", "path": "/p/ask", "body": body}
    args[change] = {"body": b'{"x":2}', "path": "/p/link", "method": "GET", "secret": b"t" * 40}[change]
    with pytest.raises(core.Refused, match="bad signature"):
        core.check_request(args["secret"], core.Nonces(), args["method"], args["path"], headers, args["body"], T0)


def test_stale_and_unsigned_and_no_secret():
    headers = core.sign_request(SECRET, "GET", "/p/answer/q1", b"", now=T0)
    with pytest.raises(core.Refused, match="stale"):
        core.check_request(SECRET, core.Nonces(), "GET", "/p/answer/q1", headers, b"", T0 + core.MAX_SKEW + 1)
    with pytest.raises(core.Refused, match="unsigned"):
        core.check_request(SECRET, core.Nonces(), "GET", "/p/answer/q1", {}, b"", T0)
    with pytest.raises(core.Refused) as error:
        core.check_request(None, core.Nonces(), "GET", "/p/answer/q1", headers, b"", T0)
    assert error.value.status == 503


def test_response_is_bound_to_the_request_nonce():
    body = json.dumps({"state": "answered", "token": "b" * 20}).encode()
    given = core.mac(SECRET, core.response_message("nonce-aaaaaaaaaaaa", 200, body))
    assert core.check_response(SECRET, "nonce-aaaaaaaaaaaa", 200, body, given)
    assert not core.check_response(SECRET, "nonce-bbbbbbbbbbbb", 200, body, given)
    assert not core.check_response(SECRET, "nonce-aaaaaaaaaaaa", 404, body, given)
    assert not core.check_response(SECRET, "nonce-aaaaaaaaaaaa", 200, body + b" ", given)


def test_nonces_are_forgotten_after_twice_the_skew():
    nonces = core.Nonces()
    assert nonces.use("n" * 16, T0)
    assert not nonces.use("n" * 16, T0 + 2 * core.MAX_SKEW)
    assert nonces.use("n" * 16, T0 + 2 * core.MAX_SKEW + 1 + 2 * core.MAX_SKEW)


# --- questions ---------------------------------------------------------------------------------------------------

def test_tokens_never_reach_the_poll():
    qs = core.Questions()
    question = ask(qs)
    content = json.dumps(core.poll_start_content(question))
    for answer in question.answers:
        assert answer.token not in content
        assert answer.id in content and answer.label in content
    assert core.POLL_DISCLOSED in content


def test_first_vote_of_the_approver_counts_only():
    qs = core.Questions()
    question = ask(qs)
    qs.bind(question, "$poll")
    einmal, ablehnen = question.answers[1], question.answers[0]
    assert qs.vote("$poll", "@other:example.org", [einmal.id], APPROVER, T0 + 1) is None
    assert qs.answer("q1") == {"state": "open"}
    assert qs.vote("$poll", APPROVER, [einmal.id], APPROVER, T0 + 2) is question
    assert qs.vote("$poll", APPROVER, [ablehnen.id], APPROVER, T0 + 3) is None
    assert qs.answer("q1") == {"state": "answered", "token": "b" * 20}


def test_bad_votes_change_nothing():
    qs = core.Questions()
    question = ask(qs)
    qs.bind(question, "$poll")
    assert qs.vote("$other", APPROVER, [question.answers[1].id], APPROVER, T0) is None
    assert qs.vote("$poll", APPROVER, ["nope"], APPROVER, T0) is None
    assert qs.vote("$poll", APPROVER, [], APPROVER, T0) is None
    assert qs.vote(None, APPROVER, [question.answers[1].id], APPROVER, T0) is None
    assert qs.answer("q1") == {"state": "open"}


def test_expiry_and_late_vote():
    qs = core.Questions()
    question = ask(qs, timeout=60)
    qs.bind(question, "$poll")
    assert qs.expire(T0 + 59) == []
    assert qs.vote("$poll", APPROVER, [question.answers[1].id], APPROVER, T0 + 60) is None
    assert qs.expire(T0 + 60) == [question]
    assert qs.expire(T0 + 61) == []
    assert qs.answer("q1") == {"state": "expired"}
    qs.prune(T0 + 60 + core.KEEP_DONE + 1)
    with pytest.raises(core.Refused, match="unknown"):
        qs.answer("q1")


def test_close_ends_without_token():
    qs = core.Questions()
    question = ask(qs)
    qs.bind(question, "$poll")
    assert qs.close("q1", "Einmal", T0) is question
    assert qs.close("q1", "Einmal", T0) is None
    assert qs.vote("$poll", APPROVER, [question.answers[1].id], APPROVER, T0) is None
    assert qs.answer("q1") == {"state": "closed"}


@pytest.mark.parametrize("data, message", [
    ({"id": "bad id", "question": "x", "answers": []}, "bad id"),
    ({"id": "q", "question": "", "answers": []}, "bad question"),
    ({"id": "q", "question": "x", "answers": [{"label": "a", "token": "a" * 20}]}, "need 2 to 8"),
    ({"id": "q", "question": "x", "answers": [{"label": "a", "token": "a" * 20}, {"label": "a", "token": "b" * 20}]},
     "repeated answer label"),
    ({"id": "q", "question": "x", "answers": [{"label": "a", "token": "a" * 20}, {"label": "b", "token": "a" * 20}]},
     "repeated answer token"),
    ({"id": "q", "question": "x", "answers": [{"label": "a", "token": "short"}, {"label": "b", "token": "b" * 20}]},
     "bad or repeated answer token"),
    ({"id": "q", "question": "x", "timeout": True,
      "answers": [{"label": "a", "token": "a" * 20}, {"label": "b", "token": "b" * 20}]}, "bad timeout"),
    ({"id": "q", "question": "x", "timeout": 10,
      "answers": [{"label": "a", "token": "a" * 20}, {"label": "b", "token": "b" * 20}]}, "bad timeout"),
])
def test_ask_validation(data, message):
    with pytest.raises(core.Refused, match=message):
        core.Questions().add(data, 900, T0)


def test_duplicate_id_and_open_limit():
    qs = core.Questions()
    ask(qs, "q1")
    with pytest.raises(core.Refused) as error:
        ask(qs, "q1")
    assert error.value.status == 409
    for n in range(2, core.OPEN_MAX + 1):
        ask(qs, f"q{n}")
    with pytest.raises(core.Refused) as error:
        ask(qs, "one-more")
    assert error.value.status == 429


def test_response_parsing():
    content = {"m.relates_to": {"rel_type": "m.reference", "event_id": "$poll"},
               core.POLL_RESPONSE: {"answers": ["abc"]}}
    assert core.response_answers(content) == ("$poll", ["abc"])
    assert core.response_answers({core.POLL_RESPONSE: {"answers": ["abc"]}}) == (None, [])
    assert core.response_answers({"m.relates_to": {"rel_type": "m.annotation", "event_id": "$p"}}) == (None, [])


def test_poll_end_content():
    content = core.poll_end_content("$poll", "Antwort: Einmal")
    assert content["m.relates_to"] == {"rel_type": "m.reference", "event_id": "$poll"}
    assert core.POLL_END in content and content["body"] == "Antwort: Einmal"


@pytest.mark.parametrize("url, ok", [("https://x.example/a?b=c", True), ("http://192.0.2.10:8080/x", True),
                                     ("javascript:alert(1)", False), ("https://a b", False), ("ftp://x", False)])
def test_link_urls(url, ok):
    if ok:
        assert core.link_text({"text": "Veröffentlicht", "url": url}) == ("Veröffentlicht", url)
    else:
        with pytest.raises(core.Refused):
            core.link_text({"text": "x", "url": url})


# --- detail and strict ---------------------------------------------------------------------------------------------

def ask_strict(qs, qid="s1", detail="automation:\n  - id: x\n", now=T0):
    data = {"id": qid, "question": "Darf ha-config-apply plan-1 laufen?", "detail": detail,
            "answers": [{"label": "Ablehnen", "token": "a" * 20}], "strict": {"token": "d" * 20}}
    return qs.add(data, 900, now)


def test_code_is_lowercase_and_digits_without_lookalikes():
    for _ in range(200):
        code = core.make_code()
        assert len(code) == core.CODE_LEN and set(code) <= set(core.CODE_ALPHABET)
    assert not set("0o1l") & set(core.CODE_ALPHABET)


def test_strict_needs_only_the_refusal_and_a_distinct_token():
    qs = core.Questions()
    q = ask_strict(qs)
    assert q.code and q.code_token == "d" * 20 and q.code_label == "Freigegeben"
    with pytest.raises(core.Refused, match="repeated answer token"):
        qs.add({"id": "s2", "question": "x", "answers": [{"label": "Ablehnen", "token": "d" * 20}],
                "strict": {"token": "d" * 20}}, 900, T0)
    with pytest.raises(core.Refused, match="need 2 to 8"):
        qs.add({"id": "s3", "question": "x", "answers": [{"label": "Ablehnen", "token": "a" * 20}]}, 900, T0)


def test_detail_limits():
    qs = core.Questions()
    with pytest.raises(core.Refused) as error:
        ask_strict(qs, detail="x" * (core.DETAIL_MAX + 1))
    assert error.value.status == 413
    with pytest.raises(core.Refused, match="bad detail"):
        ask_strict(qs, detail="  ")
    # Within DETAIL_MAX but escaping blows the HTML up past one event: refused before any poll is sent.
    with pytest.raises(core.Refused, match="too long for one Matrix event"):
        ask_strict(qs, qid="s4", detail="<" * core.DETAIL_MAX)
    assert "s4" not in qs.items


def test_thread_content_has_detail_then_code_and_no_token():
    qs = core.Questions()
    q = ask_strict(qs, detail="a: <b>")
    content = core.thread_content(q, "$poll")
    assert content["m.relates_to"]["rel_type"] == "m.thread" and content["m.relates_to"]["event_id"] == "$poll"
    assert content["body"].index("a: <b>") < content["body"].index(q.code)
    assert "&lt;b&gt;" in content["formatted_body"]
    assert "d" * 20 not in json.dumps(content) and "a" * 20 not in json.dumps(content)
    assert core.STRICT_HINT in core.poll_start_content(q)[core.POLL_START]["question"]["body"]


@pytest.mark.parametrize("typed", ["{code}", "  {code} ", "{upper}", "> <@sbx:x> Freigeben\n\n{code}"])
def test_right_code_approves(typed):
    qs = core.Questions()
    q = ask_strict(qs)
    qs.bind(q, "$poll")
    text = typed.format(code=q.code, upper=q.code.capitalize())
    question, ok = qs.code_reply("$poll", APPROVER, text, APPROVER, T0 + 5)
    assert ok and qs.answer("s1") == {"state": "answered", "token": "d" * 20}


def test_wrong_code_refuses_and_there_is_no_second_attempt():
    qs = core.Questions()
    q = ask_strict(qs)
    qs.bind(q, "$poll")
    question, ok = qs.code_reply("$poll", APPROVER, "warum?", APPROVER, T0 + 5)
    assert not ok and qs.answer("s1") == {"state": "answered", "token": "a" * 20}
    assert qs.code_reply("$poll", APPROVER, q.code, APPROVER, T0 + 6) is None
    assert qs.answer("s1")["token"] == "a" * 20


def test_code_reply_ignores_others_late_and_plain_questions():
    qs = core.Questions()
    q = ask_strict(qs)
    qs.bind(q, "$poll")
    assert qs.code_reply("$poll", "@other:x", q.code, APPROVER, T0 + 5) is None
    assert qs.code_reply("$other", APPROVER, q.code, APPROVER, T0 + 5) is None
    assert qs.code_reply("$poll", APPROVER, q.code, APPROVER, T0 + 901) is None
    assert qs.answer("s1") == {"state": "open"}
    plain = ask(qs, qid="p1")
    qs.bind(plain, "$plain")
    assert qs.code_reply("$plain", APPROVER, "abc", APPROVER, T0 + 5) is None


def test_refusal_by_poll_still_works_on_strict():
    qs = core.Questions()
    q = ask_strict(qs)
    qs.bind(q, "$poll")
    assert qs.vote("$poll", APPROVER, [q.answers[0].id], APPROVER, T0 + 5) is not None
    assert qs.answer("s1")["token"] == "a" * 20
    assert qs.code_reply("$poll", APPROVER, q.code, APPROVER, T0 + 6) is None


def test_thread_root():
    assert core.thread_root({"m.relates_to": {"rel_type": "m.thread", "event_id": "$r"}}) == "$r"
    assert core.thread_root({"m.relates_to": {"rel_type": "m.reference", "event_id": "$r"}}) is None
    assert core.thread_root({}) is None
