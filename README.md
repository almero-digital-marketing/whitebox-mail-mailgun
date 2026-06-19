# whitebox-mail-mailgun

[Mailgun](https://www.mailgun.com/) provider for `whitebox-server-plugin-mail`. Lives in its own repo; the mail plugin stays provider-agnostic and composes this in like any other integration.

```js
import { mail } from 'whitebox-server-plugin-mail'
import { mailgun } from 'whitebox-mail-mailgun'

mail({
  provider: mailgun({
    apiKey:            process.env.WB_MAILGUN_API_KEY,
    domain:            process.env.WB_MAILGUN_DOMAIN,
    webhookSigningKey: process.env.WB_MAILGUN_WEBHOOK_SIGNING_KEY,
    // replayWindowMs: 5 * 60 * 1000,   // reject webhook signatures older than this
  }),
  company: 'team@example.com',
  auth: { secret: process.env.WB_MAIL_TOKEN },
})
```

## What it implements

The neutral mail-provider contract the plugin consumes:

| method | Mailgun specifics |
|---|---|
| `send(msg) → { messageId }` | nodemailer Mailgun transport; `o:tracking` header; `noreply@{domain}` default from; strips `<>` from the message id |
| `sendBatch(messages)` + `maxBatchSize: 1000` | uniform body → one `recipient-variables` call (ids null, backfilled from webhooks by recipient); personalized → concurrent individual sends with real per-recipient ids |
| `verifySignature(req, kind)` | HMAC-SHA256 over `timestamp+token`; inbound posts the fields flat, tracking nests them under `signature`; replay-window check |
| `parseInbound(req)` | `sender`/`recipient`/`stripped-text`/`body-html` + multipart file attachments |
| `parseTracking(req)` | `event-data` envelope → canonical event (`failed→bounced`, etc.); `severity`, recipient, error message |
| `ownsAddress(addr)` | matches the sending domain (used for inbound `to` resolution) |
| `classifyError(err)` | HTTP 4xx / known rejection keywords ⇒ permanent (blocklist instead of retry) |

## Webhook setup

Both endpoints are public but **HMAC-verified** by this provider — Mailgun signs every request with your webhook signing key, and the plugin rejects anything unsigned, stale (outside the replay window), or tampered.

**1. Signing key.** Mailgun dashboard → **Settings → Webhook signing key**. Put it in `WB_MAILGUN_WEBHOOK_SIGNING_KEY`. The same key verifies both inbound and tracking.

**2. Tracking events.** Mailgun → **Send → Webhooks** (for your sending domain). Point each of these at `https://YOUR_HOST/mail/webhooks/tracking`:

| Mailgun event | canonical | effect in WhiteBox |
|---|---|---|
| Delivered | `delivered` | outbox status → delivered |
| Opened | `opened` | → opened, recorded in awareness |
| Clicked | `clicked` | → engaged, recorded in awareness |
| Permanent Failure | `bounced` | hard bounce → **invalid** list |
| Complained (spam) | `complained` | → **suppression** list |
| Unsubscribed | `unsubscribed` | → **suppression** list |

These POST `application/json` with Mailgun's `event-data` + `signature` envelope. Opens/clicks are only reported for mail sent with tracking on — the outbox worker sets `o:tracking` per send (default on).

**3. Inbound mail / replies.** Mailgun → **Receiving → Create Route**:
- Expression — e.g. `match_recipient(".*@YOUR_DOMAIN")`
- Action — `forward("https://YOUR_HOST/mail/webhooks/inbox")`

Routes POST `multipart/form-data` (attachments arrive as files); the same endpoint also accepts JSON, so it works regardless of Mailgun's format.

Both webhook routes live under the mail plugin's mount (`/mail`), so the full URLs are `https://YOUR_HOST/mail/webhooks/tracking` and `…/mail/webhooks/inbox`.

## Credentials

All from the environment — never commit them:

- `WB_MAILGUN_API_KEY`
- `WB_MAILGUN_DOMAIN`
- `WB_MAILGUN_WEBHOOK_SIGNING_KEY`
