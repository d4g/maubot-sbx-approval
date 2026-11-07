# maubot-sbx-approval

A [maubot](https://github.com/maubot/maubot) plugin that asks one person in one end-to-end encrypted Matrix room to approve
an action, as a poll, and hands the answer back to the program that asked over a small HTTP API.

It is the Matrix channel for the approvals of an agent sandbox (`sbx`): before a tool runs, `sbx` posts the question and
one random token per answer; the plugin starts a poll in the room, takes the **first** vote of the configured user only,
ends the poll, and returns the token of the chosen answer. A question nobody answers ends as expired after a timeout.
It can also post plain links (shared or published files) into the same room.

**Status:** design only, no code yet. The design and the reasons behind it are recorded in the homelab repository's
ADR 0024 ("Approvals and links of the agent sandbox through Matrix").

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

## Deployment

Built on NixOS with `fetchFromGitHub` and **pinned to a commit hash**; a change here runs only after the pin is changed
on the host.

## License

[Unlicense](LICENSE) — public domain.
