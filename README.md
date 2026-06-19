# whitebox-mail-mailgun

[Mailgun](https://www.mailgun.com/) provider for [`whitebox-server-plugin-mail`](../../whitebox-server-plugin-mail). Lives in its own repo; the mail plugin stays provider-agnostic and composes this in like any other integration.

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
| `verifySignature(req, kind)` | HMAC-SHA256 over `timestamp+token`; inbound posts the fields flat, tracking nests them under `signature`; replay-window check |
| `parseInbound(req)` | `sender`/`recipient`/`stripped-text`/`body-html` + multipart file attachments |
| `parseTracking(req)` | `event-data` envelope → canonical event (`failed→bounced`, etc.); `severity`, recipient, error message |
| `ownsAddress(addr)` | matches the sending domain (used for inbound `to` resolution) |
| `classifyError(err)` | HTTP 4xx / known rejection keywords ⇒ permanent (blocklist instead of retry) |

## Webhooks

Point your Mailgun routes/webhooks at the plugin's endpoints (both signature-verified):

- inbound messages → `POST /mail/webhooks/inbox`
- tracking events (delivered/opened/clicked/failed/complained/unsubscribed) → `POST /mail/webhooks/tracking`

## Credentials

All from the environment — never commit them:

- `WB_MAILGUN_API_KEY`
- `WB_MAILGUN_DOMAIN`
- `WB_MAILGUN_WEBHOOK_SIGNING_KEY`
