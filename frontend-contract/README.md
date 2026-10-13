# Evedentia frontend contract

`openapi.json` is the full schema (also live at http://localhost:8000/docs). Generate TypeScript types with e.g.
`npx openapi-typescript frontend-contract/openapi.json -o src/api.d.ts`.
Regenerate after backend changes: `docker compose exec -T backend python scripts/export_openapi.py > frontend-contract/openapi.json`.

## Rules for every request

- Base URL `http://localhost:8000`. Use `fetch(..., { credentials: "include" })` (or axios `withCredentials`). The session is the
  httpOnly cookie `ev_session` (7 days). CORS allows credentials from `http://localhost:5173`.
- Not signed in -> **401** `{"detail": "not signed in"}`. Send the user to the Sign in screen.
- Every error is `{"detail": "<string>"}` (including 422 validation errors).
- Lists return `{ items, next_cursor }`. Pass `next_cursor` back as `?cursor=` until it is `null`. `?limit=` default 25, max 100.
- Someone else's message id returns **404** (same as a missing one).
- **All message fields are attacker-controlled text** (`sender`, `preview`, `subject`, `body_text`, `urls`, reasons, evidence). Render as
  plain text only: no `dangerouslySetInnerHTML`, no `<a href>` for urls (show them as plain text), no auto-linking, no `<img>`.
- Bands: `URGENT` (red), `REVIEW` (amber), `INSUFFICIENT_DATA` (grey "Couldn't fully check"), `LOW` (no badge).
- `readable: false` = we could not parse that email. Show it as "Couldn't read this email" (grey), not as safe.

## Screens

### 1. Sign in
| What | Endpoint |
| --- | --- |
| Button "Continue with Google" | **Navigate** the browser to `GET /auth/google` (not fetch). After consent the backend sets the cookie and redirects to `FRONTEND_URL/inbox` |
| Sign-in failed | Backend redirects to `FRONTEND_URL/login?error=domain` (wrong work domain), `oauth` (Google error) or `email` (unverified) |
| Who am I / am I signed in | `GET /me` -> `{id, name, email, title, gmail_connected, whatsapp_number}`; 401 = signed out |
| Gmail permission not granted | Lands on `/inbox?error=gmail_scope`: user is signed in but `gmail_connected` is false. Show "Connect Gmail" (= `GET /auth/google` again) |

### 2. Inbox check
| What | Endpoint |
| --- | --- |
| List, riskiest first (URGENT, REVIEW, INSUFFICIENT_DATA, LOW, then newest) | `GET /me/messages?band=&channel=&limit=&cursor=` |
| Item fields | `id, channel, source, sender, sender_display_name, preview, received_at, risk_band, top_reason, colleague_count, escalated, readable` |
| "Check now" button | `POST /scan` -> `{new_messages}` (409 if Gmail not connected/revoked, 502 if Gmail unreachable). Then refetch the list. The server also polls every minute |

### 3. Message detail
| What | Endpoint |
| --- | --- |
| Open a message | `GET /me/messages/{id}`: body as plain text, `urls`, `attachments` (metadata only), `assessment {risk_band, reasons[{code,text,evidence_ids}], evidence[], data_completeness, colleague_count}`, `what_to_do[]` (render as the "what to do next" list), `escalated_at`, `feedback` |
| Clicking a reason shows its evidence | Match `reason.evidence_ids` to `assessment.evidence[].evidence_id`. `status` is `found`, `not_found` or `not_checked` (show "not checked", never as clean) |
| "Report to IT" | `POST /me/messages/{id}/escalate` body `{note?: string (max 500)}` -> `{id, message_id, sent_to, sent_at, employee_note}`. Safe to call twice (returns the first). **502** = email failed, nothing saved, show "Try again" |
| "This is fine" | `POST /me/messages/{id}/feedback` body `{verdict: "fine"}` |
| "Also sent to N colleagues" | `assessment.colleague_count` (0 until the campaign linker exists; hide when 0) |

### 4. Check a message
| What | Endpoint |
| --- | --- |
| Paste an SMS/WhatsApp message | `POST /check` JSON `{channel: "sms" \| "whatsapp", sender, text}` (text max 5,000 chars) |
| Upload an .eml | `POST /check` multipart, field `file`, max 2 MB (413 if bigger) |
| Result | Same shape as `GET /me/messages/{id}`: render with the Message detail screen |

### 5. My reports
| What | Endpoint |
| --- | --- |
| Things I submitted via Check a message or the WhatsApp bot, newest first | `GET /me/reports?band=&channel=&limit=&cursor=` (same item shape as the inbox list); open one with `GET /me/messages/{id}` |

### 6. Settings
| What | Endpoint |
| --- | --- |
| Show/save WhatsApp number | `PATCH /me` body `{whatsapp_number: "+91 98765 43210" \| null}` (stored as E.164; 422 invalid, 409 already used) |
| Disconnect Gmail | `POST /auth/gmail/disconnect` -> `{gmail_connected: false}` |
| Sign out | `POST /auth/logout` -> `{ok: true}` |

### Admin (no screen needed; for seeding)
`POST /admin/users/import` (CSV upload), `GET /admin/users`: admins only (403 otherwise).

## Demo data

`docker compose exec backend python -m app.seed --me you@gmail.com` creates 3 employees (you become the first, an admin) and 11 messages
across all bands, including two employees who received the same "CEO bank change" email.
