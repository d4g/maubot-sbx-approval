# maubot-sbx-approval

A [maubot](https://github.com/maubot/maubot) plugin that asks one person in one end-to-end encrypted Matrix room to approve
an action, as a poll, and hands the answer back to the program that asked over a small HTTP API.

It is the Matrix channel for the approvals of an agent sandbox (`sbx`): before a tool runs, `sbx` posts the question and
one random token per answer; the plugin starts a poll in the room, takes the **first** vote of the configured user only,
ends the poll, and returns the token of the chosen answer. A question nobody answers ends as expired after a timeout.
It can also post plain links (shared or published files) into the same room.

**Status:** written and tested off-line (logic, and the HTTP endpoints of the real plugin class against maubot 0.6.0 /
mautrix 0.21.1 with a fake Matrix client); not yet run in maubot. The design and the reasons behind it are recorded in
the homelab repository's ADR 0024 ("Approvals and links of the agent sandbox through Matrix").

## Design in brief

- **Poll format:** MSC3381 with the unstable prefix `org.matrix.msc3381.poll.*`, which Element uses; kind
  `org.matrix.msc3381.poll.disclosed`, so the choice shows at once.
- **One room, one user.** The bot account runs with autojoin off; the room ID and the user's MXID are instance config.
  Votes from anyone else, and any vote after the first, change nothing.
- **HTTP API** through maubot's plugin web app (`/_matrix/maubot/plugin/<instance>/…`):
  `POST /ask` (question id, text, one token per answer), `GET /answer/<id>` (the chosen token, or still open / expired),
  `POST /link` (a message with a link).
- **Signed with HMAC**, requests and responses, over a shared secret with timestamp and nonce. The secret never crosses
  the wire, so someone who can read the LAN traffic cannot forge an answer.
- **Nothing site-specific in this repository.** Secret, room and user live in maubot's instance config.

## API

All under the instance's web path, `<maubot>/_matrix/maubot/plugin/<instance id>/`. Every request is signed (below);
an unsigned, wrongly signed, stale or replayed request gets `401` without a signature, and `503` while no secret is set.

| Request | Body | Answer (signed) |
|---|---|---|
| `POST /ask` | `{"id", "question", "answers": [{"label", "token"}, …], "timeout"?}` — 2 to 8 answers, labels ≤ 40 characters, tokens 16 to 128 of `[A-Za-z0-9_-]`, timeout 30 to 3600 s (default from the config) | `201 {"id"}`; `409` id used, `429` 50 open questions, `502` poll not sent |
| `GET /answer/<id>` | — | `200 {"state": "open" \| "expired" \| "closed"}` or `{"state": "answered", "token"}`; `404` unknown (also after a maubot restart: questions live in memory) |
| `POST /close/<id>` | `{"label"?}` | `200 {"closed": bool}` — the caller got its answer elsewhere; the poll ends as "Beantwortet über das Telefon" |
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
