# maubot-sbx-approval

A [maubot](https://github.com/maubot/maubot) plugin that asks one person in one end-to-end encrypted Matrix room to approve
an action, as a poll, and hands the answer back to the program that asked over a small HTTP API.

It is the Matrix channel for the approvals of an agent sandbox (`sbx`): before a tool runs, `sbx` posts the question and
one random token per answer; the plugin starts a poll in the room, takes the **first** vote of the configured user only,
ends the poll, and returns the token of the chosen answer. A question nobody answers ends as expired after a timeout.
It can also post plain links (shared or published files) into the same room.

**Status:** in use with maubot 0.6.0; tested off-line (logic, and the HTTP endpoints of the real plugin class against
maubot 0.6.0 / mautrix 0.21.1 with a fake Matrix client, routed as maubot routes them). The design and the reasons behind it are recorded in
the homelab repository's ADR 0024 ("Approvals and links of the agent sandbox through Matrix").

## Design in brief

- **Poll format:** MSC3381 with the unstable prefix `org.matrix.msc3381.poll.*`, which Element uses; kind
  `org.matrix.msc3381.poll.disclosed`, so the choice shows at once.
- **One room, one user.** The bot account runs with autojoin off; the room ID and the user's MXID are instance config.
  Votes from anyone else, and any vote after the first, change nothing.
- **HTTP API** through maubot's plugin web app (`/_matrix/maubot/plugin/<instance>/…`):
  `POST /ask` (question id, text, one token per answer), `GET /answer/<id>` (the chosen token, or still open / expired),
  `POST /close/<id>` (the answer came elsewhere), `POST /link` (a message with a link).
- **Signed with HMAC**, requests and responses, over a shared secret with timestamp and nonce. The secret never crosses
  the wire, so someone who can read the LAN traffic cannot forge an answer.
- **Nothing site-specific in this repository.** Secret, room and user live in maubot's instance config.

## API

All under the instance's web path, `<maubot>/_matrix/maubot/plugin/<instance id>/`. Every request is signed (below);
an unsigned, wrongly signed, stale or replayed request gets `401` without a signature, and `503` while no secret is set.

| Request | Body | Answer (signed) |
|---|---|---|
| `POST /ask` | `{"id", "question", "answers": [{"label", "token"}, …], "timeout"?, "detail"?, "strict"?: {"token", "label"?}}` — 2 to 8 answers (1 to 8 with `strict`), labels ≤ 40 characters, tokens 16 to 128 of `[A-Za-z0-9_-]`, timeout 30 to 3600 s (default from the config), `detail` ≤ 16 KiB UTF-8 | `201 {"id"}`; `409` id used, `413` detail too long, `429` 50 open questions, `502` poll or thread not sent |
| `GET /answer/<id>` | — | `200 {"state": "open" \| "expired" \| "closed"}` or `{"state": "answered", "token"}`; `404` unknown (also after a maubot restart: questions live in memory) |
| `POST /close/<id>` | `{"label"?, "reason"?}` | `200 {"closed": bool}` — the caller got its answer elsewhere; the poll ends as "Beantwortet über das Telefon" (with the label), or with `"reason": "replaced"` as "Ersetzt durch eine neue Frage" |
| `POST /link` | `{"text", "url"}` — `http(s)` only | `201 {"sent": true}` |

The answer tokens never reach Matrix: the poll gets random answer ids, and only the plugin maps them back.

**Signature.** Headers `X-Sbx-Time` (Unix seconds), `X-Sbx-Nonce` (16 to 64 of `[A-Za-z0-9_-]`, fresh per request) and
`X-Sbx-Mac`, the hex HMAC-SHA256 with the shared secret over these lines joined by `\n`:

```text
sbx-approval-request
<METHOD>
<path below the instance, e.g. /answer/q1 — maubot strips /_matrix/maubot/plugin/<instance> before the plugin sees it>
<X-Sbx-Time>
<X-Sbx-Nonce>
<hex SHA-256 of the body>
```

Requests more than 60 s off the plugin's clock, or with a nonce seen in the last 120 s, are refused. A signed answer
carries `X-Sbx-Mac` over `sbx-approval-response`, the request's nonce, the status code and the body's SHA-256, joined
the same way; a caller must check it before it trusts the answer. `core.sign_request` and `core.check_response` are
the reference.

**Votes.** Only a poll response in the configured room, from the configured approver, sent encrypted, on an open
question, counts, and only the first; the plugin then ends the poll with the chosen answer. An open question ends as
"Abgelaufen, keine Antwort" after its timeout.

**Detail in a thread.** With `detail` (e.g. the diff of a change), the plugin posts it as a code block in a thread
on the poll (`rel_type: m.thread`), so the room's main timeline shows only the short poll. The whole thread message must
stay under 40 KiB as plaintext, so the encrypted event stays under Matrix's 65536 bytes; a detail that HTML escaping
blows up beyond that is refused with `413` before the poll is sent. If the thread message cannot be sent, the poll is
ended as "Abgebrochen" and `/ask` answers `502`.

**Strict questions** guard against approving by reflex, the way number matching does for MFA pushes. With `strict`,
the plugin makes a code of 6 characters from lowercase letters and digits, without the look-alikes `0`, `o`, `1`
and `l` (easy on a phone keyboard), and posts it in the thread **after** the detail. The poll carries only the
answers given (normally just the refusal) and the line "Freigeben nur mit dem Code im Thread.". The approver approves by
replying in the thread with the code; the plugin compares it without blanks and case (a phone capitalises the first
letter) and ignores quoted reply-fallback lines. **There is one attempt:** any other reply of the approver in that
thread counts as the first answer (the refusal), so a wrong code cannot be followed by a right one. A right code
answers with `strict.token` and the label `strict.label` (default "Freigegeben"). The code is made in the plugin and
reaches only the encrypted room; it never crosses the plain-HTTP link between caller and plugin. Thread replies count
under the same rules as votes: configured room, configured approver, encrypted, open question.

## Configuration

Per instance in the maubot UI ([`base-config.yaml`](base-config.yaml)): `room_id`, `approver`, `secret` (≥ 32
characters), `timeout`. The bot account should run with autojoin off and be in that one room only.

## Tests

```bash
uv run --no-project --python 3.13 --with maubot==0.6.0 --with pytest --with pytest-aiohttp pytest tests
```

`tests/test_core.py` needs only pytest; `tests/test_web.py` is skipped without maubot.

## Deployment

Built on NixOS with `fetchFromGitHub` and **pinned to a commit hash**; a change here runs only after the pin is changed
on the host.

## Avatar

[`assets/avatar.jpg`](assets/avatar.jpg) is the bot account's avatar (256×256, uploaded in the maubot UI on the client).
Generated 2026-11-07 with FLUX 3 Image Klein distilled (ComfyUI, 1024×1024, 16 steps, cfg 1, prompt upsampler on,
seed 856283351522516), then cropped to the tile and scaled down. Prompt:

```text
A minimalist flat vector app icon, centered on a plain solid background: a small friendly robot head inside a square sandbox frame, with a large green check mark and a red cross badge at its side, symbolising approval. Bold simple shapes, thick clean outlines, two to three colours (deep teal, warm white, signal green), high contrast, no text, no gradients, no small details, generous empty margin around the subject so it survives a circular crop, readable at 32 pixels.
```

## License

[Unlicense](LICENSE) — public domain.
