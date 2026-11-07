"""The HTTP endpoints and the vote handler of the real plugin class, with a fake Matrix client.

Needs maubot (skipped without it): uv run --no-project --python 3.13 --with maubot==0.6.0 --with pytest
--with pytest-aiohttp pytest tests
"""
import asyncio
import json
import logging
import pathlib
import sys

import pytest

pytest.importorskip("maubot")
from aiohttp import web  # noqa: E402
from maubot.plugin_server import PluginWebApp, PrefixResource  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sbx_approval  # noqa: E402
from sbx_approval import core  # noqa: E402

SECRET = "s" * 40
ROOM = "!room:example.org"
APPROVER = "@dag:example.org"
BOT = "@sbx:example.org"
PREFIX = "/_matrix/maubot/plugin/sbx"


class FakeClient:
    mxid = BOT

    def __init__(self):
        self.sent = []

    async def send_message_event(self, room_id, event_type, content):
        self.sent.append((room_id, str(event_type), content))
        return f"$ev{len(self.sent)}"

    async def send_message(self, room_id, content):
        self.sent.append((room_id, "m.room.message", content.serialize()))
        return f"$ev{len(self.sent)}"


class FakeEvent:
    def __init__(self, content, sender=APPROVER, room_id=ROOM, encrypted=True):
        self.content, self.sender, self.room_id = content, sender, room_id
        self._mautrix = {"was_encrypted": True} if encrypted else None

    def get(self, key):
        return self._mautrix if key == "mautrix" else None


def make_plugin():
    plugin = object.__new__(sbx_approval.SbxApproval)
    plugin.config = {"room_id": ROOM, "approver": APPROVER, "secret": SECRET, "timeout": 900}
    plugin.client = FakeClient()
    plugin.log = logging.getLogger("test")
    plugin.questions = core.Questions()
    plugin.nonces = core.Nonces()
    plugin.lock = asyncio.Lock()
    return plugin


@pytest.fixture
async def setup(aiohttp_client):
    """Routed the way maubot 0.6.0 routes plugin web apps (maubot/server.py, handle_plugin_path): a PrefixResource
    for the plugin base path, and the instance prefix cut off the path before the plugin's PluginWebApp sees it.
    The routes come from the plugin's own @web decorators."""
    plugin = make_plugin()
    sub = PluginWebApp()
    for name in dir(plugin):
        for method, path, kwargs in getattr(getattr(plugin, name), "__mb_web_handler__", []):
            sub.add_route(method=method, path=path, handler=getattr(plugin, name), **kwargs)
    instance_path = PREFIX + "/"

    async def handle_plugin_path(request):
        if request.path.startswith(instance_path):
            request = request.clone(rel_url=request.rel_url.with_path(
                request.rel_url.path[len(instance_path) - 1:]).with_query(request.query_string))
            return await sub.handle(request)
        return web.Response(status=404)

    app = web.Application()
    resource = PrefixResource("/_matrix/maubot/plugin")
    resource.add_route("*", handle_plugin_path)
    app.router.register_resource(resource)
    return plugin, await aiohttp_client(app)


async def call(client, method, path, data=None, secret=SECRET):
    body = json.dumps(data).encode() if data is not None else b""
    headers = core.sign_request(secret.encode(), method, path, body)  # signed: the path below the instance
    resp = await client.request(method, PREFIX + path, data=body, headers=headers)
    raw = await resp.read()
    signed = core.check_response(SECRET.encode(), headers["X-Sbx-Nonce"], resp.status, raw,
                                 resp.headers.get("X-Sbx-Mac", ""))
    return resp.status, json.loads(raw), signed


QUESTION = {"id": "q1", "question": "Darf ha-call laufen?",
            "answers": [{"label": "Ablehnen", "token": "a" * 20}, {"label": "Einmal", "token": "b" * 20}]}


async def test_ask_vote_answer(setup):
    plugin, client = setup
    assert await call(client, "POST", "/ask", QUESTION) == (201, {"id": "q1"}, True)
    room, kind, content = plugin.client.sent[0]
    assert (room, kind) == (ROOM, core.POLL_START)
    assert "b" * 20 not in json.dumps(content)
    assert await call(client, "GET", "/answer/q1") == (200, {"state": "open"}, True)

    einmal = content[core.POLL_START]["answers"][1]["id"]
    vote = {"m.relates_to": {"rel_type": "m.reference", "event_id": "$ev1"}, core.POLL_RESPONSE: {"answers": [einmal]}}
    await plugin.on_response(FakeEvent(vote, sender="@other:example.org"))
    await plugin.on_response(FakeEvent(vote, encrypted=False))
    assert await call(client, "GET", "/answer/q1") == (200, {"state": "open"}, True)
    await plugin.on_response(FakeEvent(vote))
    assert await call(client, "GET", "/answer/q1") == (200, {"state": "answered", "token": "b" * 20}, True)
    assert plugin.client.sent[-1][1] == core.POLL_END


async def test_wrong_secret_and_replay(setup):
    plugin, client = setup
    status, body, signed = await call(client, "POST", "/ask", QUESTION, secret="x" * 40)
    assert (status, body, signed) == (401, {"error": "bad signature"}, False)
    assert plugin.client.sent == []
    headers = core.sign_request(SECRET.encode(), "GET", "/answer/q1", b"")
    first = await client.get(PREFIX + "/answer/q1", headers=headers)
    second = await client.get(PREFIX + "/answer/q1", headers=headers)
    assert first.status == 404 and second.status == 401


async def test_close_and_link(setup):
    plugin, client = setup
    await call(client, "POST", "/ask", QUESTION)
    assert await call(client, "POST", "/close/q1", {"label": "Einmal"}) == (200, {"closed": True}, True)
    assert plugin.client.sent[-1][2]["body"] == "Beantwortet über das Telefon: Einmal"
    assert await call(client, "GET", "/answer/q1") == (200, {"state": "closed"}, True)
    assert await call(client, "POST", "/close/q1", {}) == (200, {"closed": False}, True)
    await call(client, "POST", "/ask", dict(QUESTION, id="q2"))
    assert await call(client, "POST", "/close/q2", {"reason": "replaced"}) == (200, {"closed": True}, True)
    assert plugin.client.sent[-1][2]["body"] == "Ersetzt durch eine neue Frage"
    status, _, signed = await call(client, "POST", "/link", {"text": "Bild <b>", "url": "https://x.example/p?a=1&b=2"})
    assert (status, signed) == (201, True)
    html = plugin.client.sent[-1][2]["formatted_body"]
    assert "&lt;b&gt;" in html and "a=1&amp;b=2" in html


async def test_no_secret(setup):
    plugin, client = setup
    plugin.config["secret"] = "short"
    status, _, signed = await call(client, "POST", "/ask", QUESTION)
    assert (status, signed) == (503, False)


async def test_full_path_signature_is_refused(setup):
    """The path maubot hands the plugin has no instance prefix; a caller signing the full URL path fails."""
    plugin, client = setup
    body = json.dumps(QUESTION).encode()
    headers = core.sign_request(SECRET.encode(), "POST", PREFIX + "/ask", body)
    resp = await client.post(PREFIX + "/ask", data=body, headers=headers)
    assert resp.status == 401 and (await resp.json()) == {"error": "bad signature"}


STRICT = {"id": "s1", "question": "Darf ha-config-apply laufen?", "detail": "alias: Test\nmode: single\n",
          "answers": [{"label": "Ablehnen", "token": "a" * 20}], "strict": {"token": "d" * 20}}


def thread_msg(body, root="$ev1", **kw):
    return FakeEvent({"msgtype": "m.text", "body": body,
                      "m.relates_to": {"rel_type": "m.thread", "event_id": root}}, **kw)


async def test_strict_code_in_thread(setup):
    plugin, client = setup
    assert await call(client, "POST", "/ask", STRICT) == (201, {"id": "s1"}, True)
    (_, kind1, poll), (_, kind2, thread) = plugin.client.sent
    assert kind1 == core.POLL_START and kind2 == "m.room.message"
    assert thread["m.relates_to"]["event_id"] == "$ev1" and "alias: Test" in thread["body"]
    code = plugin.questions.items["s1"].code
    assert code in thread["body"] and code not in json.dumps(poll)
    assert "d" * 20 not in json.dumps(plugin.client.sent)

    await plugin.on_message(thread_msg(code, sender="@other:example.org"))
    await plugin.on_message(thread_msg(code, encrypted=False))
    await plugin.on_message(thread_msg(code, root="$elsewhere"))
    assert await call(client, "GET", "/answer/s1") == (200, {"state": "open"}, True)
    await plugin.on_message(thread_msg(code.upper()))
    assert await call(client, "GET", "/answer/s1") == (200, {"state": "answered", "token": "d" * 20}, True)
    note, end = plugin.client.sent[-2][2], plugin.client.sent[-1]
    assert note["body"] == "Code stimmt: freigegeben." and end[1] == core.POLL_END
    assert end[2]["body"] == "Antwort: Freigegeben (Code)"


async def test_strict_wrong_code(setup):
    plugin, client = setup
    await call(client, "POST", "/ask", STRICT)
    await plugin.on_message(thread_msg("falsch"))
    assert await call(client, "GET", "/answer/s1") == (200, {"state": "answered", "token": "a" * 20}, True)
    assert plugin.client.sent[-1][2]["body"] == "Antwort: Ablehnen (falscher Code)"


async def test_detail_without_strict_and_too_long(setup):
    plugin, client = setup
    assert (await call(client, "POST", "/ask", dict(QUESTION, detail="diff")))[0] == 201
    assert plugin.client.sent[-1][2]["body"] == "diff"
    status, body, signed = await call(client, "POST", "/ask", dict(STRICT, id="s9", detail="x" * (core.DETAIL_MAX + 1)))
    assert (status, signed) == (413, False)


async def test_thread_send_failure_ends_the_question(setup):
    plugin, client = setup
    sent = plugin.client.send_message_event

    async def fail_thread(room_id, event_type, content):
        if str(event_type) == "m.room.message":
            raise RuntimeError("no")
        return await sent(room_id, event_type, content)

    plugin.client.send_message_event = fail_thread
    status, body, signed = await call(client, "POST", "/ask", STRICT)
    assert (status, body, signed) == (502, {"error": "could not send the thread"}, True)
    assert plugin.questions.items["s1"].state == "closed"
    assert plugin.client.sent[-1][1] == core.POLL_END
