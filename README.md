# Evedentia

Employee app that checks emails/SMS/WhatsApp messages for phishing and social engineering.
Platform in `backend/app/`, analysis engine in `backend/engine/` (Member B), shared contract in `backend/shared/schemas.py`.

## Run

```bash
cp .env.example .env          # fill in secrets (FERNET_KEY, Google, Twilio) when needed
docker compose up -d --build  # postgres, mailpit (UI :8025), ollama, backend (:8000)
docker compose exec backend alembic upgrade head
docker compose exec backend pytest
curl localhost:8000/health    # {"status":"ok"}
```

API docs: http://localhost:8000/docs

## Contract for Member B

Schemas: `backend/shared/schemas.py` (`AttachmentMeta`, `NormalizedMessage`, `Evidence`, `Reason`, `Assessment`).

Replace the stubs, keeping the signatures:

- `engine/parser.py`: `parse_mime(raw: bytes, user_id: int, external_id: str) -> NormalizedMessage`
- `engine/analyze.py`: `analyze(msg: NormalizedMessage) -> Assessment`

Employee lookups for sender/impersonation checks: `app/services/directory.py`
(`find_by_email`, `find_by_phone`, `find_by_name`; phones normalized to E.164, default region IN).

Rules: message content is data only; never fetch URLs or open attachments; a failed check is
`not_checked`/`INSUFFICIENT_DATA`, never safe; never log bodies, tokens or secrets.

## Google sign-in + Gmail (read-only)

1. Google Cloud Console: create a project, then **APIs & Services > Library > Gmail API > Enable**.
2. **OAuth consent screen**: user type External, add scopes `openid`, `email`, `profile`,
   `.../auth/gmail.readonly`. While the app is in *Testing*, add every demo Google account under **Test users**.
3. **Credentials > Create credentials > OAuth client ID > Web application**.
   Authorized redirect URI: `http://localhost:8000/auth/google/callback`.
4. Put the client ID/secret in `.env` (`GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`), generate keys if empty:
   `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"` -> `FERNET_KEY`.
   Optionally set `ALLOWED_EMAIL_DOMAIN` (e.g. `corp.com`) to restrict sign-in to a Workspace domain.
5. `docker compose up -d`, then open http://localhost:8000/auth/google. After consent you land on
   `FRONTEND_URL/inbox` with an `ev_session` cookie; `GET /me` shows `gmail_connected: true`.

Refresh tokens are stored Fernet-encrypted. `POST /auth/gmail/disconnect` revokes and clears them.

## Employee API (Phase 4)

Open http://localhost:8000/docs. Auth is the `ev_session` cookie from Google sign-in; send requests with `credentials: "include"`.
Errors are always `{"detail": "..."}`. Lists use `?limit=` (default 25, max 100) and an opaque `?cursor=`.

- `GET /me/messages` riskiest first; `GET /me/reports` messages submitted via `/check` or WhatsApp; `GET /me/messages/{id}`.
- `POST /me/messages/{id}/escalate` (Report to IT, idempotent), `POST /me/messages/{id}/feedback`.
- `POST /check`: JSON `{channel, sender, text}` or multipart `.eml` (field `file`, max 2 MB).
- `POST /admin/users/import` (CSV `name,title,email,phone`) and `GET /admin/users` need an admin (`is_admin` or `ADMIN_EMAILS`).
- Escalation emails go to `IT_SECURITY_EMAIL` over SMTP (Mailpit UI at http://localhost:8025 in dev); set `SMTP_USER`/`SMTP_PASSWORD` to use STARTTLS + login.

Tests run in the container against their own `evedentia_test` database: `docker compose exec backend pytest`.

## WhatsApp bot setup (Twilio sandbox)

1. Twilio Console -> Messaging -> Try it out -> Send a WhatsApp message. Note the sandbox number and the join code
   (`join <two-words>`). **Every test phone must send that join code to the sandbox number once** (it expires after ~72 h of silence).
2. Put `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN` and `TWILIO_WHATSAPP_FROM` (`whatsapp:+14155238886`, the sandbox number) in `.env`.
3. Run `ngrok http 8000`. Copy the `https://....ngrok-free.app` URL.
4. Set `PUBLIC_BASE_URL=https://<that-ngrok-url>` in `.env`. It must match exactly: the Twilio signature is checked against
   `PUBLIC_BASE_URL + /webhooks/twilio/whatsapp`, because ngrok rewrites the host.
5. Recreate the backend so it reads the new `.env`: `docker compose up -d backend`.
6. Twilio Console -> Sandbox settings -> **When a message comes in**: `https://<ngrok-url>/webhooks/twilio/whatsapp`, method **POST**. Save.
7. Register your number: sign in to the web app, then `PATCH /me` with `{"whatsapp_number": "+91 98765 43210"}` (docs page: http://localhost:8000/docs).
8. On the phone: share or paste a suspicious SMS to the sandbox chat, answer who sent it (or `skip`), read the verdict, reply `escalate`.

The free ngrok URL changes on every restart: repeat steps 3-6 each time.
Commands: `help`, `report` (start over), `status`, `escalate [note]`. Only a message that is exactly a command counts as one.
Without the three Twilio settings the webhook answers 503 and logs why.

## Swapping in the real engine (Member B)

Replace the stubs in `backend/engine/` (`parser.py`: `parse_mime(raw, user_id, external_id)`, `analyze.py`: `analyze(msg)`), then:

```bash
docker compose exec backend python scripts/swap_check.py   # runs every tests/fixtures/*.eml through parse -> analyze -> process_message
docker compose exec backend pytest                         # the stub-specific tests in test_basic.py may need updating
```

Demo data: `docker compose exec backend python -m app.seed --me you@gmail.com`. Frontend contract: `frontend-contract/`.
