import { describe, it, expect, vi, beforeEach } from 'vitest'
import crypto from 'crypto'

// Mock the nodemailer transport so send() never touches the network.
const sendMail = vi.fn(async () => ({ messageId: '<abc-123@mg.example.com>' }))
vi.mock('nodemailer', () => ({ default: { createTransport: () => ({ sendMail }) } }))
vi.mock('nodemailer-mailgun-transport', () => ({ default: () => ({}) }))

const { mailgun } = await import('../src/index.js')

const KEY = 'whsec_test'
function freshSig() {
  const timestamp = String(Math.floor(Date.now() / 1000))
  const token = 'tok-' + timestamp
  const signature = crypto.createHmac('sha256', KEY).update(timestamp + token).digest('hex')
  return { timestamp, token, signature }
}

function make() {
  return mailgun({ apiKey: 'key-x', domain: 'mg.example.com', webhookSigningKey: KEY })
}

beforeEach(() => sendMail.mockClear())

describe('contract', () => {
  it('exposes the provider methods', () => {
    const p = make()
    expect(p.name).toBe('mailgun')
    for (const m of ['send', 'verifySignature', 'parseInbound', 'parseTracking', 'ownsAddress', 'classifyError']) {
      expect(typeof p[m]).toBe('function')
    }
  })

  it('throws without apiKey/domain', () => {
    expect(() => mailgun({ domain: 'x' })).toThrow(/apiKey and domain/)
    expect(() => mailgun({ apiKey: 'x' })).toThrow(/apiKey and domain/)
  })
})

describe('send', () => {
  it('defaults from, sets tracking, and strips <> from the messageId', async () => {
    const p = make()
    const out = await p.send({ to: 'a@b.com', subject: 'Hi', html: '<p>x</p>', track: true, attachments: [{ filename: 'f.pdf', path: '/tmp/f.pdf' }] })
    expect(out).toEqual({ messageId: 'abc-123@mg.example.com' })
    const arg = sendMail.mock.calls[0][0]
    expect(arg.from).toBe('noreply@mg.example.com')
    expect(arg['o:tracking']).toBe('yes')
    expect(arg.attachments).toEqual([{ filename: 'f.pdf', path: '/tmp/f.pdf' }])
  })

  it('honors an explicit from and track=false', async () => {
    const p = make()
    await p.send({ from: 'me@x.com', to: 'a@b.com', subject: 'Hi', text: 'x' })
    const arg = sendMail.mock.calls[0][0]
    expect(arg.from).toBe('me@x.com')
    expect(arg['o:tracking']).toBe('no')
  })
})

describe('verifySignature', () => {
  it('accepts a valid inbound (flat) signature', () => {
    const p = make()
    const sig = freshSig()
    expect(p.verifySignature({ body: sig }, 'inbound')).toBe(true)
  })

  it('accepts a valid tracking (nested) signature', () => {
    const p = make()
    const sig = freshSig()
    expect(p.verifySignature({ body: { signature: sig } }, 'tracking')).toBe(true)
  })

  it('rejects a tampered signature', () => {
    const p = make()
    const sig = freshSig()
    expect(p.verifySignature({ body: { ...sig, signature: 'deadbeef' } }, 'inbound')).toBe(false)
  })

  it('rejects a stale timestamp', () => {
    const p = make()
    const old = String(Math.floor(Date.now() / 1000) - 3600)
    const token = 't'
    const signature = crypto.createHmac('sha256', KEY).update(old + token).digest('hex')
    expect(p.verifySignature({ body: { timestamp: old, token, signature } }, 'inbound')).toBe(false)
  })

  it('rejects missing fields', () => {
    const p = make()
    expect(p.verifySignature({ body: {} }, 'inbound')).toBe(false)
  })
})

describe('parseInbound', () => {
  it('maps Mailgun multipart fields + files', () => {
    const p = make()
    const req = {
      body: { sender: 'a@b.com', recipient: 'in@mg.example.com', subject: 'Re: x', 'stripped-text': 'hello', 'body-html': '<p>hello</p>' },
      files: [{ originalname: 'r.png', buffer: Buffer.from('img') }],
    }
    expect(p.parseInbound(req)).toEqual({
      from: 'a@b.com',
      to: 'in@mg.example.com',
      subject: 'Re: x',
      body: 'hello',
      bodyHtml: '<p>hello</p>',
      attachments: [{ filename: 'r.png', content: Buffer.from('img') }],
    })
  })
})

describe('parseTracking', () => {
  it.each([
    ['delivered', 'delivered'],
    ['opened', 'opened'],
    ['clicked', 'clicked'],
    ['failed', 'bounced'],
    ['complained', 'complained'],
    ['unsubscribed', 'unsubscribed'],
  ])('maps event %s → canonical %s', (mg, canonical) => {
    const p = make()
    const req = { body: { 'event-data': { event: mg, recipient: 'a@b.com', message: { headers: { 'message-id': 'mid-1' } }, severity: 'permanent' } } }
    const out = p.parseTracking(req)
    expect(out.event).toBe(canonical)
    expect(out.messageId).toBe('mid-1')
    expect(out.recipient).toBe('a@b.com')
    expect(out.severity).toBe('permanent')
  })

  it('returns null without event-data', () => {
    expect(make().parseTracking({ body: {} })).toBe(null)
  })
})

describe('ownsAddress + classifyError', () => {
  it('ownsAddress matches the sending domain', () => {
    const p = make()
    expect(p.ownsAddress('hi@mg.example.com')).toBe(true)
    expect(p.ownsAddress('hi@elsewhere.com')).toBe(false)
  })

  it('classifies 4xx and keyword errors as permanent, 5xx as transient', () => {
    const p = make()
    expect(p.classifyError({ statusCode: 400, message: 'Bad' }).permanent).toBe(true)
    expect(p.classifyError({ message: 'user unknown' }).permanent).toBe(true)
    expect(p.classifyError({ statusCode: 503, message: 'temporary' }).permanent).toBe(false)
  })
})
