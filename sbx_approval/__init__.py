"""maubot glue of sbx-approval: the HTTP endpoints, the poll events, and a timer for expiry. Logic in core.py."""
from __future__ import annotations

import asyncio
import json
import time

from aiohttp.web import Request, Response
from maubot import Plugin
from maubot.handlers import event, web
from mautrix.types import EventType, Format, MessageType, TextMessageEventContent
from mautrix.util.config import BaseProxyConfig, ConfigUpdateHelper

from . import core

POLL_START = EventType.find(core.POLL_START, EventType.Class.MESSAGE)
POLL_RESPONSE = EventType.find(core.POLL_RESPONSE, EventType.Class.MESSAGE)
POLL_END = EventType.find(core.POLL_END, EventType.Class.MESSAGE)
BODY_MAX = 16 * 1024
TICK = 10


class Config(BaseProxyConfig):
    def do_update(self, helper: ConfigUpdateHelper) -> None:
        for key in ("room_id", "approver", "secret", "timeout"):
            helper.copy(key)


class SbxApproval(Plugin):
    questions: core.Questions
    nonces: core.Nonces
    lock: asyncio.Lock
    ticker: asyncio.Task | None = None

    @classmethod
    def get_config_class(cls) -> type[BaseProxyConfig]:
        return Config

    async def start(self) -> None:
        self.config.load_and_update()
        self.questions = core.Questions()
        self.nonces = core.Nonces()
        self.lock = asyncio.Lock()
        self.ticker = asyncio.get_running_loop().create_task(self._tick())
        if self._secret() is None:
            self.log.warning("secret missing or shorter than %d characters: every request is refused", core.SECRET_MIN)

    async def stop(self) -> None:
        if self.ticker:
            self.ticker.cancel()

    def on_external_config_update(self) -> None:
        self.config.load_and_update()

    def _secret(self) -> bytes | None:
        secret = self.config["secret"] or ""
        return secret.encode() if len(secret) >= core.SECRET_MIN else None

    # --- HTTP -------------------------------------------------------------------------------------------------

    async def _read(self, request: Request) -> tuple[str, bytes]:
        if request.content_length is not None and request.content_length > BODY_MAX:
            raise core.Refused(413, "body too large")
        body = await request.content.read(BODY_MAX + 1)
        if len(body) > BODY_MAX:
            raise core.Refused(413, "body too large")
        nonce = core.check_request(self._secret(), self.nonces, request.method, request.path, request.headers, body,
                                   time.time())
        return nonce, body

    def _reply(self, nonce: str, status: int, data: dict) -> Response:
        body = json.dumps(data, separators=(",", ":")).encode()
        secret = self._secret()
        headers = {"X-Sbx-Mac": core.mac(secret, core.response_message(nonce, status, body))} if secret else {}
        return Response(status=status, body=body, content_type="application/json", headers=headers)

    @staticmethod
    def _refused(error: core.Refused) -> Response:
        # Unsigned on purpose: the caller treats any unsigned answer as a failure of this channel.
        return Response(status=error.status, text=json.dumps({"error": error.message}), content_type="application/json")

    @staticmethod
    def _json(body: bytes):
        try:
            return json.loads(body)
        except ValueError:
            raise core.Refused(400, "body is not JSON")

    @web.post("/ask")
    async def ask(self, request: Request) -> Response:
        try:
            nonce, body = await self._read(request)
            async with self.lock:
                question = self.questions.add(self._json(body), self.config["timeout"], time.time())
                try:
                    event_id = await self.client.send_message_event(self.config["room_id"], POLL_START,
                                                                    core.poll_start_content(question))
                except Exception:
                    self.questions.drop(question)
                    self.log.exception("could not send the poll for %s", question.qid)
                    return self._reply(nonce, 502, {"error": "could not send the poll"})
                self.questions.bind(question, event_id)
            return self._reply(nonce, 201, {"id": question.qid})
        except core.Refused as error:
            return self._refused(error)

    @web.get("/answer/{qid}")
    async def answer(self, request: Request) -> Response:
        try:
            nonce, _ = await self._read(request)
            return self._reply(nonce, 200, self.questions.answer(request.match_info["qid"]))
        except core.Refused as error:
            return self._refused(error)

    @web.post("/close/{qid}")
    async def close(self, request: Request) -> Response:
        try:
            nonce, body = await self._read(request)
            data = self._json(body) if body else {}
            label = data.get("label") if isinstance(data, dict) else None
            label = label if isinstance(label, str) and len(label) <= core.LABEL_MAX else None
            replaced = isinstance(data, dict) and data.get("reason") == "replaced"
            async with self.lock:
                question = self.questions.close(request.match_info["qid"], label, time.time())
            if question is not None:
                await self._end(question, "Ersetzt durch eine neue Frage" if replaced
                                else "Beantwortet über das Telefon" + (f": {label}" if label else ""))
            return self._reply(nonce, 200, {"closed": question is not None})
        except core.Refused as error:
            return self._refused(error)

    @web.post("/link")
    async def link(self, request: Request) -> Response:
        try:
            nonce, body = await self._read(request)
            text, url = core.link_text(self._json(body))
            content = TextMessageEventContent(msgtype=MessageType.TEXT, body=f"{text}\n{url}", format=Format.HTML,
                                              formatted_body=f"{_html(text)}<br><a href=\"{_html(url)}\">{_html(url)}</a>")
            await self.client.send_message(self.config["room_id"], content)
            return self._reply(nonce, 201, {"sent": True})
        except core.Refused as error:
            return self._refused(error)

    # --- Matrix -----------------------------------------------------------------------------------------------

    @event.on(POLL_RESPONSE)
    async def on_response(self, evt) -> None:
        if evt.room_id != self.config["room_id"] or evt.sender == self.client.mxid:
            return
        marker = evt.get("mautrix") or {}
        if not marker.get("was_encrypted"):
            self.log.warning("ignored an unencrypted poll response from %s", evt.sender)
            return
        content = evt.content.serialize() if hasattr(evt.content, "serialize") else dict(evt.content)
        poll_id, answer_ids = core.response_answers(content)
        async with self.lock:
            question = self.questions.vote(poll_id, evt.sender, answer_ids, self.config["approver"], time.time())
        if question is not None:
            self.log.info("question %s answered: %s", question.qid, question.label)
            await self._end(question, f"Antwort: {question.label}")

    async def _end(self, question: core.Question, text: str) -> None:
        if not question.event_id:
            return
        try:
            await self.client.send_message_event(self.config["room_id"], POLL_END,
                                                 core.poll_end_content(question.event_id, text))
        except Exception:
            self.log.exception("could not end the poll of %s", question.qid)

    async def _tick(self) -> None:
        while True:
            await asyncio.sleep(TICK)
            try:
                now = time.time()
                async with self.lock:
                    ended = self.questions.expire(now)
                    self.questions.prune(now)
                    self.nonces.prune(now)
                for question in ended:
                    await self._end(question, "Abgelaufen, keine Antwort")
            except asyncio.CancelledError:
                raise
            except Exception:
                self.log.exception("expiry timer")


def _html(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
