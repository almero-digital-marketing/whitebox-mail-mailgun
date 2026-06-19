import crypto from 'crypto'
import nodemailer from 'nodemailer'
import mg from 'nodemailer-mailgun-transport'

// Mailgun provider for whitebox-server-plugin-mail. Implements the neutral mail
// provider contract — the plugin owns the outbox/queue/suppressions/awareness
// plumbing; everything Mailgun-specific (transport, HMAC webhook auth, payload
// shapes) lives here. Compose it in config: mail({ provider: mailgun({ … }) }).

const DEFAULT_REPLAY_WINDOW_MS = 5 * 60 * 1000

// Permanent-error classifier: HTTP 4xx OR known rejection keywords. A permanent
// error means the address is unusable, so the plugin blocklists it instead of
// retrying.
const PERMANENT_PATTERNS = /invalid|no recipients|syntax|address rejected|not a valid email|free user|not allowed|does not exist|user unknown|mailbox/i

// Mailgun event name → whitebox canonical event vocabulary the plugin consumes.
const EVENT_MAP = {
  delivered:    'delivered',
  opened:       'opened',
  clicked:      'clicked',
  failed:       'bounced',
  complained:   'complained',
  unsubscribed: 'unsubscribed',
}

function timingSafeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false
  try {
    return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
  } catch {
    return false
  }
}

export function mailgun({ apiKey, domain, webhookSigningKey, replayWindowMs = DEFAULT_REPLAY_WINDOW_MS } = {}) {
  if (!apiKey || !domain) {
    throw new Error('mailgun(): apiKey and domain are required')
  }

  const transport = nodemailer.createTransport(mg({ auth: { api_key: apiKey, domain } }))

  function isFresh(timestamp) {
    const ts = Number(timestamp) * 1000
    if (!Number.isFinite(ts)) return false
    return Math.abs(Date.now() - ts) <= replayWindowMs
  }

  // Mailgun signs webhooks with HMAC-SHA256 over (timestamp + token), keyed by
  // the webhook signing key. Inbound posts the fields flat; tracking nests them
  // under `signature`.
  function verifyHmac(sig) {
    if (!webhookSigningKey) return false
    if (!sig?.timestamp || !sig?.token || !sig?.signature) return false
    if (!isFresh(sig.timestamp)) return false
    const expected = crypto.createHmac('sha256', webhookSigningKey).update(sig.timestamp + sig.token).digest('hex')
    return timingSafeHexEqual(expected, String(sig.signature))
  }

  return {
    name: 'mailgun',

    async send({ from, to, replyTo, subject, html, text, headers, attachments = [], track = false }) {
      const info = await transport.sendMail({
        from: from || `noreply@${domain}`,
        to,
        replyTo,
        subject,
        html,
        text,
        headers,
        // The plugin resolves saved attachments to { filename, path }; the
        // nodemailer transport reads them straight off disk.
        attachments: attachments.map(a => ({ filename: a.filename, path: a.path })),
        'o:tracking': track ? 'yes' : 'no',
      })
      // Mailgun wraps the id in angle brackets; strip so tracking webhooks match.
      return { messageId: info?.messageId?.replace(/[<>]/g, '') || null }
    },

    // kind: 'inbound' (flat body fields) | 'tracking' (nested under signature)
    verifySignature(req, kind) {
      const sig = kind === 'tracking'
        ? req.body?.signature
        : { timestamp: req.body?.timestamp, token: req.body?.token, signature: req.body?.signature }
      return verifyHmac(sig)
    },

    parseInbound(req) {
      const b = req.body || {}
      return {
        from:     b.sender || b.from,
        to:       b.recipient || null,
        subject:  b.subject,
        // Mailgun separates the reply from quoted history into stripped-text.
        body:     b['stripped-text'] || b['body-plain'] || null,
        bodyHtml: b['body-html'] || null,
        attachments: (req.files || []).map(f => ({ filename: f.originalname, content: f.buffer })),
      }
    },

    parseTracking(req) {
      const d = req.body?.['event-data']
      if (!d) return null
      return {
        messageId:    d?.message?.headers?.['message-id'] || null,
        event:        EVENT_MAP[d.event] || d.event,
        recipient:    d.recipient || null,
        severity:     d.severity || null,
        errorMessage: d?.['delivery-status']?.message || d?.reason || null,
      }
    },

    // The plugin keeps an explicit inbound `to` only when we own the address.
    ownsAddress(addr) {
      return typeof addr === 'string' && addr.endsWith(`@${domain}`)
    },

    classifyError(err) {
      if (!err) return { permanent: false }
      const code = err.statusCode ?? err.status ?? err.responseCode
      const numeric = typeof code === 'number' ? code : parseInt(code, 10)
      const is4xx = Number.isFinite(numeric) && numeric >= 400 && numeric < 500
      const msg = String(err.message || '')
      return {
        permanent: is4xx || PERMANENT_PATTERNS.test(msg),
        statusCode: Number.isFinite(numeric) ? numeric : null,
        message: msg,
      }
    },
  }
}

export default mailgun
