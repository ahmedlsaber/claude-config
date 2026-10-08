# Global preferences

## Web / browsing tasks
When a task needs the live web — searching, fetching a page, checking a site, scraping, or verifying something online — use a browser MCP rather than guessing:
- **agent-browser** (`mcp__agent-browser__*`) — preferred for interactive automation (navigate, snapshot, click, fill, read).
- **playwright** (`mcp__playwright__*`) — fallback / when agent-browser is unavailable.

Prefer `agent_browser_read` or `snapshot` for reading content, `snapshot` before clicking to get stable refs.
# graphify
- **graphify** (`~/.claude/skills/graphify/SKILL.md`) - any input to knowledge graph. Trigger: `/graphify`
When the user types `/graphify`, use the installed graphify skill or instructions before doing anything else.

## Disposable email (mail.tm) for test accounts
Use the **mail.tm API** to create disposable inboxes for registering owned test accounts (bug bounty / pentest). It is the default mail service — use it automatically each session when a test-account signup needs an email, do not ask.

API base: `https://api.mail.tm`
- `GET  /domains` -> active domain(s), e.g. `emalupe.com`
- `POST /accounts` `{"address":"<local>@<domain>","password":"<pw>"}` -> creates inbox
- `POST /token` `{"address":...,"password":...}` -> `{token,id}` (Bearer for the rest)
- `GET  /messages` (Bearer) -> list; `GET /messages/{id}` -> full message incl. body/html
- Flow: create account -> immediately POST /token to get a working JWT (registration returns 422 if the inbox name is taken; pick a random suffix and retry).
- Inboxes are disposable and can receive verification mail within seconds; poll `GET /messages` until the message arrives.
- Save each test account's address/password to the engagement's `credentials.md` (gitignored target dir); never commit.
- NOTE: emalupe.com is the shared domain (matches existing halara test accounts) — use a unique random local-part per test.
