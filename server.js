// backend/server.js
require('dotenv').config()

const express = require('express')
const helmet = require('helmet')
const cookieParser = require('cookie-parser')
const cors = require('cors')
const fs = require('fs')
const path = require('path')
const nodemailer = require('nodemailer')
const bodyParser = require('body-parser')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const rateLimit = require('express-rate-limit')

/* --------------------- Config & constants --------------------- */
const app = express()
const PORT = process.env.PORT || 4000
const FRONTEND_ORIGIN = (process.env.FRONTEND_ORIGIN || 'http://localhost:5173').replace(/\/$/, '')
const REQ_FILE = path.join(__dirname, 'requests.json')
const EXPORT_FILE = path.join(__dirname, 'exported_projects.json')

const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_strong_secret'
const JWT_EXPIRES = process.env.JWT_EXPIRES || '8h'
const COOKIE_NAME = 'nakart_admin_token'

/* --------------------- Security middleware --------------------- */
app.use(helmet())
app.use(cookieParser())

// CORS: only allow the configured frontend origin(s)
const allowedOrigins = [
  FRONTEND_ORIGIN,
  (process.env.ADDITIONAL_ALLOWED_ORIGIN || '').replace(/\/$/, ''), // optional extra origin
  'https://www.nakartdesigns.store',
  'https://nakartdesigns.store'
].filter(Boolean)

app.use(cors({
  origin: function (origin, callback) {
    // allow non-browser requests (postman, curl) without origin
    if (!origin) return callback(null, true)
    if (allowedOrigins.includes(origin)) return callback(null, true)
    return callback(new Error('Not allowed by CORS'))
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

// ensure preflight handler responds with credentials header
app.options('*', (req, res) => {
  res.header('Access-Control-Allow-Credentials', 'true')
  res.header('Access-Control-Allow-Origin', req.headers.origin || '')
  res.sendStatus(204)
})

app.use(bodyParser.json({ limit: '20mb' }))

// Rate limits
const loginLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 6,
  message: { ok: false, error: 'Too many login attempts, try again shortly' }
})
const generalLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 300
})
app.use('/api/', generalLimiter)

/* --------------------- Mailer (nodemailer) --------------------- */
let transporter
;(function createTransporter() {
  const smtpUser = process.env.SMTP_USER
  const smtpPass = process.env.SMTP_PASS
  const smtpHost = process.env.SMTP_HOST
  const smtpPort = process.env.SMTP_PORT
  const smtpSecure = process.env.SMTP_SECURE

  // Basic TLS fallback config if you explicitly set SKIP_TLS_VERIFY=true (dev only)
  const tlsOpts = (String(process.env.SKIP_TLS_VERIFY || 'false') === 'true') ? { tls: { rejectUnauthorized: false } } : {}

  if (smtpUser && smtpPass) {
    transporter = nodemailer.createTransport(Object.assign({
      host: smtpHost || 'smtp.gmail.com',
      port: Number(smtpPort) || 465,
      secure: (String(smtpSecure) === 'true') || true,
      auth: { user: smtpUser, pass: smtpPass }
    }, tlsOpts))
    return
  }

  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    transporter = nodemailer.createTransport(Object.assign({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
    }, tlsOpts))
    return
  }

  // No-auth transport (best-effort; many providers will reject)
  transporter = nodemailer.createTransport(Object.assign({
    host: smtpHost || 'smtp.gmail.com',
    port: Number(smtpPort) || 465,
    secure: true
  }, tlsOpts))
})()

transporter.verify((err) => {
  if (err) console.warn('SMTP verify failed:', err && err.message ? err.message : err)
  else console.log('SMTP ready')
})

/* --------------------- Utilities --------------------- */
function safe(str) {
  const map = { '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;', "'":'&#39;','/':'&#x2F;','`':'&#x60;','=':'&#x3D;' }
  return String(str || '').replace(/[&<>"'`=\/]/g, s => map[s] || s)
}

function readRequestsFile() {
  try {
    if (!fs.existsSync(REQ_FILE)) return []
    const raw = fs.readFileSync(REQ_FILE, 'utf8')
    return JSON.parse(raw || '[]')
  } catch (e) {
    console.warn('readRequestsFile err', e)
    return []
  }
}

// safer write (atomic-ish) and used everywhere
function writeRequestsFile(list) {
  try {
    const tmp = `${REQ_FILE}.tmp`
    fs.writeFileSync(tmp, JSON.stringify(list || [], null, 2), 'utf8')
    fs.renameSync(tmp, REQ_FILE)
  } catch (e) {
    console.warn('writeRequestsFile err', e)
  }
}

// Save request, but avoid duplicates (by id). This prevents retries creating duplicates.
function saveRequestToFile(obj) {
  try {
    const list = readRequestsFile()
    if (list.find(r => String(r.id) === String(obj.id))) {
      // already exists -> replace with latest copy
      const idx = list.findIndex(r => String(r.id) === String(obj.id))
      list[idx] = obj
      writeRequestsFile(list)
      return
    }
    list.unshift(obj)
    writeRequestsFile(list)
  } catch (e) {
    console.warn('saveRequestToFile err', e)
  }
}

/* --------------------- Email templates (no attachment by default) --------------------- */
const COLORS = {
  burgundy: process.env.BRAND_BURGUNDY || '#B02A37',
  plum: process.env.BRAND_PLUM || '#502C5A',
  navy: process.env.BRAND_NAVY || '#1D1B4D',
  canvas: process.env.BRAND_CANVAS || '#F9F9F9'
}

function headerBlock(title, subtitle) {
  const logoUrl = process.env.LOGO_URL || ''
  const gradient = `linear-gradient(135deg, ${COLORS.plum} 0%, ${COLORS.burgundy} 100%)`
  const escapedTitle = safe(title)
  const escapedSubtitle = safe(subtitle || '')
  const headerContent = logoUrl
    ? `<div style="display:flex;gap:12px;align-items:center;justify-content:center">
         <img src="${safe(logoUrl)}" alt="${escapedTitle}" style="height:48px; display:block; border-radius:8px; object-fit:contain" />
         <div style="font-family: 'Georgia','Garamond',serif;color:white;font-weight:700;font-size:22px;letter-spacing:0.6px">${escapedTitle}</div>
       </div>`
    : `<div style="font-family: 'Georgia', 'Garamond', serif; font-weight:700; font-size:22px; letter-spacing:1.2px; text-transform:uppercase; color:white; line-height:1.2">${escapedTitle}</div>`

  return `
    <div style="background: ${gradient}; padding:22px 18px; color:white; text-align:center;">
      <div style="max-width:640px; margin:0 auto;">
        ${headerContent}
        ${escapedSubtitle ? `<div style="font-size:13px; opacity:0.95; margin-top:8px; font-weight:500">${escapedSubtitle}</div>` : ''}
      </div>
    </div>
  `
}

function wrapEmail(innerHtml, smallPrint='') {
  return `
    <div style="font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial; background:${COLORS.canvas}; padding:18px;">
      <div style="max-width:700px; margin:0 auto; background:#fff; border-radius:12px; overflow:hidden; border:1px solid #eee; box-shadow:0 2px 10px rgba(0,0,0,0.05)">
        ${innerHtml}
        <div style="padding:14px 18px; background:#fafbfc; border-top:1px solid #eee; color:#666; font-size:12px; text-align:center; line-height:1.4">${safe(smallPrint)}</div>
      </div>
    </div>
  `
}

function adminHtmlEmail({ name, email, phone, service, budget, message, createdAt }) {
  const header = headerBlock('NakArt Designs', 'New project inquiry')
  const body = `
    <div style="padding:20px;">
      <div style="background:#fbfbfb;padding:12px;border-radius:8px;margin-bottom:18px">
        <table role="presentation" width="100%" style="border-collapse:collapse;">
          <tr style="border-bottom:1px solid #e6e6e6"><td style="width:28%; color:#666; padding:8px 0;font-weight:700;font-size:13px">NAME</td><td style="padding:8px 0;font-weight:700">${safe(name)}</td></tr>
          <tr style="border-bottom:1px solid #e6e6e6"><td style="color:#666; padding:8px 0;font-weight:700;font-size:13px">EMAIL</td><td style="padding:8px 0"><a href="mailto:${safe(email)}" style="color:${COLORS.burgundy};text-decoration:none">${safe(email)}</a></td></tr>
          <tr style="border-bottom:1px solid #e6e6e6"><td style="color:#666; padding:8px 0;font-weight:700;font-size:13px">PHONE</td><td style="padding:8px 0">${safe(phone || 'Not provided')}</td></tr>
          <tr style="border-bottom:1px solid #e6e6e6"><td style="color:#666; padding:8px 0;font-weight:700;font-size:13px">SERVICE</td><td style="padding:8px 0">${safe(service || 'General')}</td></tr>
          <tr><td style="color:#666; padding:8px 0;font-weight:700;font-size:13px">BUDGET</td><td style="padding:8px 0">${safe(budget || '—')}</td></tr>
        </table>
      </div>

      <div style="margin-bottom:14px">
        <div style="font-weight:700;color:${COLORS.navy};margin-bottom:8px;font-size:13px">Message</div>
        <div style="background:#fff;padding:14px;border-radius:8px;border-left:4px solid ${COLORS.burgundy};white-space:pre-wrap;color:#222">${safe(message)}</div>
      </div>

      <div style="margin-top:16px;display:flex;gap:10px">
        <a href="mailto:${safe(email)}" style="display:inline-block;padding:10px 14px;border-radius:8px;background:${COLORS.burgundy};color:#fff;text-decoration:none;font-weight:700">Reply to Client</a>
        <a href="${safe(process.env.ADMIN_DASHBOARD_URL || (FRONTEND_ORIGIN + '/admin'))}" style="display:inline-block;padding:10px 14px;border-radius:8px;background:${COLORS.plum};color:#fff;text-decoration:none;font-weight:700">Open Admin Panel</a>
      </div>

      <div style="margin-top:20px;color:#888;font-size:12px">Received: <strong>${safe(createdAt)}</strong></div>
    </div>
  `
  const small = `NakArt Designs • ${process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER || ''}`
  return wrapEmail(header + body, small)
}

function confirmationHtmlEmail({ name, service, message }) {
  const header = headerBlock('NakArt Designs', 'We received your request')
  const body = `
    <div style="padding:18px">
      <p style="margin:0 0 10px">Hi ${safe(name || 'there')},</p>
      <p style="margin:0 0 12px;color:#444">Thanks for reaching out about <strong>${safe(service || 'your project')}</strong>. I’ll review and reply within 48 hours (business days).</p>
      <div style="background:#fbfbfb;padding:12px;border-radius:8px;white-space:pre-wrap;color:#333">${safe(message)}</div>
      <div style="margin-top:14px"><a href="mailto:${safe(process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER)}" style="display:inline-block;padding:10px 14px;border-radius:8px;background:${COLORS.burgundy};color:white;text-decoration:none;font-weight:700">Contact NakArt</a></div>
      <p style="margin-top:12px;color:#666;font-size:13px">We aim to reply within 48 hours (business days).</p>
    </div>
  `
  const small = `NakArt Designs • ${process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER || ''}`
  return wrapEmail(header + body, small)
}

function replyHtmlEmail({ adminName, replyText, originalRequest }) {
  const header = headerBlock('NakArt Designs', 'Response to your inquiry')
  const body = `
    <div style="padding:20px;color:#222">
      <p style="margin:0 0 12px;font-size:15px">Hi <strong>${safe(originalRequest.name || 'there')}</strong>,</p>
      <div style="margin:12px 0 20px;font-size:15px;line-height:1.6">${safe(replyText).replace(/\n/g,'<br/>')}</div>

      <div style="margin-top:10px;padding-top:12px;border-top:1px solid #e6e6e6">
        <div style="font-weight:700;color:${COLORS.burgundy};font-size:15px">${safe(adminName)}</div>
        <div style="font-size:13px;color:#666;"><a href="mailto:${safe(process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER)}" style="color:${COLORS.navy};text-decoration:none">${safe(process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER)}</a></div>
      </div>

      <div style="margin-top:18px;background:#f9f9f9;padding:14px;border-radius:8px">
        <div style="font-size:12px;color:#666;margin-bottom:8px;font-weight:700;text-transform:uppercase">Your original message</div>
        <div style="white-space:pre-wrap;color:#444">${safe(originalRequest.message || '')}</div>
      </div>
    </div>
  `
  const small = `NakArt Designs • ${process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER || ''}`
  return wrapEmail(header + body, small)
}

/* --------------------- Validation & auth utilities --------------------- */
function validateRequestPayload(payload) {
  if (!payload) return 'Missing payload'
  if (!payload.name || !payload.email || !payload.message) return 'Missing required fields'
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(payload.email)) return 'Invalid email'
  if ((payload.message || '').trim().length < 6) return 'Message too short'
  return null
}

async function checkAdminCredentials(email, password) {
  const adminEmail = process.env.ADMIN_EMAIL
  const adminHash = process.env.ADMIN_PASSWORD_HASH
  const adminPlain = process.env.ADMIN_PASSWORD
  if (!adminEmail) return { ok:false, error:'Admin email not configured' }
  if (String(email).toLowerCase() !== String(adminEmail).toLowerCase()) return { ok:false, error:'Invalid email' }
  if (adminHash) {
    try {
      const match = await bcrypt.compare(String(password || ''), adminHash)
      return match ? { ok:true } : { ok:false, error:'Invalid password' }
    } catch(e){ return { ok:false, error:'Hash compare failed' } }
  }
  if (adminPlain) {
    return String(password) === String(adminPlain) ? { ok:true } : { ok:false, error:'Invalid password' }
  }
  return { ok:false, error:'No admin password configured on server' }
}

function requireAdminMiddleware(req, res, next) {
  const header = req.headers.authorization
  const cookieToken = req.cookies && req.cookies[COOKIE_NAME]
  const token = (header && header.startsWith('Bearer ') ? header.split(' ')[1] : null) || cookieToken
  if (!token) return res.status(401).json({ ok:false, error: 'Unauthorized' })
  try {
    const payload = jwt.verify(token, JWT_SECRET)
    if (!payload || payload.role !== 'admin') return res.status(403).json({ ok:false, error:'Forbidden' })
    req.admin = payload
    return next()
  } catch (err) {
    console.warn('JWT verify failed:', err && err.message)
    return res.status(401).json({ ok:false, error:'Invalid token' })
  }
}

/* --------------------- Routes --------------------- */

// Admin login (sets HttpOnly cookie, returns token as well)
app.post('/api/admin/login', loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body || {}
    if (!email || !password) return res.status(400).json({ ok:false, error:'Missing credentials' })
    const cred = await checkAdminCredentials(email, password)
    if (!cred.ok) return res.status(401).json({ ok:false, error: cred.error || 'Invalid credentials' })
    const token = jwt.sign({ role: 'admin', email: process.env.ADMIN_EMAIL }, JWT_SECRET, { expiresIn: JWT_EXPIRES })
    const cookieOpts = {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
    res.cookie(COOKIE_NAME, token, cookieOpts)
    return res.json({ ok:true, token })
  } catch (e) {
    console.error('/api/admin/login error', e)
    return res.status(500).json({ ok:false, error:'Login failed' })
  }
})

// Public: receive contact requests
app.post('/api/requests', async (req, res) => {
  try {
    const err = validateRequestPayload(req.body)
    if (err) return res.status(400).json({ ok:false, error: err })
    const { name, email, phone, service, budget, message } = req.body
    const createdAt = new Date().toISOString()
    const id = Date.now().toString(36)
    const obj = { id, name, email, phone, service, budget, message, createdAt }

    // persist locally (safe dedupe)
    saveRequestToFile(obj)

    // Admin email (no file attachments by default)
    try {
      const adminEmail = process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER
      if (adminEmail) {
        const html = adminHtmlEmail(obj)
        const mailOptions = {
          from: process.env.FROM_EMAIL || adminEmail,
          to: adminEmail,
          subject: `✉️ New request from ${name} — ${service || 'General'}`,
          html
        }
        console.log('[ADMIN EMAIL] send attempt ->', adminEmail)
        const info = await transporter.sendMail(mailOptions)
        console.log('[ADMIN EMAIL] Sent:', info && (info.messageId || info.response) || 'ok')
      } else {
        console.warn('Admin email not configured; skipping admin notification')
      }
    } catch (e) {
      console.error('[ADMIN EMAIL FAILED]', e && e.message || e)
    }

    // optional user confirmation
    if (String(process.env.SEND_USER_CONFIRMATION || 'false') === 'true') {
      try {
        const html = confirmationHtmlEmail({ name, service, message })
        const mailOptions = {
          from: process.env.FROM_EMAIL || (process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER),
          to: email,
          subject: 'Thanks — I received your request',
          html
        }
        console.log('[CONFIRMATION] sending to', email)
        const info = await transporter.sendMail(mailOptions)
        console.log('[CONFIRMATION] Sent:', info && (info.messageId || info.response) || 'ok')
      } catch (e) {
        console.error('[CONFIRMATION FAILED]', e && e.message || e)
      }
    }

    return res.json({ ok:true, id })
  } catch (e) {
    console.error('/api/requests error', e)
    return res.status(500).json({ ok:false, error:'Server error' })
  }
})

// Protected: list stored requests
app.get('/api/requests', requireAdminMiddleware, (req, res) => {
  try {
    const data = readRequestsFile()
    return res.json(data)
  } catch (e) {
    console.error('GET /api/requests', e)
    return res.status(500).json({ ok:false, error:'Failed to read requests' })
  }
})

// Protected: get single request
app.get('/api/requests/:id', requireAdminMiddleware, (req, res) => {
  try {
    const id = req.params.id
    const list = readRequestsFile()
    const found = list.find(r => String(r.id) === String(id))
    if (!found) return res.status(404).json({ ok:false, error:'Not found' })
    return res.json(found)
  } catch (e) {
    console.error('GET /api/requests/:id', e)
    return res.status(500).json({ ok:false, error:'Failed' })
  }
})

// Protected: delete a request
app.delete('/api/requests/:id', requireAdminMiddleware, (req, res) => {
  try {
    const id = req.params.id
    const list = readRequestsFile()
    const filtered = list.filter(r => String(r.id) !== String(id))
    writeRequestsFile(filtered)
    return res.json({ ok:true })
  } catch (e) {
    console.error('DELETE /api/requests/:id error', e)
    return res.status(500).json({ ok:false, error:'Failed to delete' })
  }
})

// Protected: respond to a request (send email reply)
app.post('/api/respond-request', requireAdminMiddleware, async (req, res) => {
  try {
    const { id, to, reply, replySubject } = req.body || {}
    if (!to || !reply) return res.status(400).json({ ok:false, error:'Missing to or reply' })
    const subject = replySubject || 'Re: Your request to NakArt Designs'
    const list = readRequestsFile()
    const original = list.find(r => String(r.id) === String(id)) || { name: '' }
    const html = replyHtmlEmail({ adminName: (req.admin && req.admin.email) ? req.admin.email : 'NakArt', replyText: reply, originalRequest: original })

    try {
      const mailOptions = {
        from: process.env.FROM_EMAIL || (process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER),
        to,
        subject,
        html
      }
      console.log('[ADMIN REPLY] sending to', to)
      const info = await transporter.sendMail(mailOptions)
      console.log('[ADMIN REPLY] Sent:', info && (info.messageId || info.response) || 'ok')

      // record reply
      try {
        const idx = list.findIndex(r => String(r.id) === String(id))
        if (idx >= 0) {
          list[idx].replies = list[idx].replies || []
          list[idx].replies.push({ by: req.admin?.email || 'admin', at: new Date().toISOString(), subject, text: reply })
          writeRequestsFile(list)
        }
      } catch (e) { console.warn('Failed to record reply', e) }

      return res.json({ ok:true })
    } catch (e) {
      console.error('[ADMIN REPLY FAILED]', e && e.message || e)
      return res.status(500).json({ ok:false, error:'Failed to send reply: ' + (e && e.message ? e.message : '') })
    }
  } catch (e) {
    console.error('respond-request error', e)
    return res.status(500).json({ ok:false, error:'Server error' })
  }
})

// Projects backup and sync endpoints
app.post('/api/projects', requireAdminMiddleware, (req, res) => {
  try {
    const data = req.body
    if (!Array.isArray(data)) return res.status(400).json({ ok:false, error:'Expected array of projects' })
    fs.writeFileSync(EXPORT_FILE, JSON.stringify(data, null, 2), 'utf8')
    return res.json({ ok:true, savedTo: EXPORT_FILE })
  } catch (e) {
    console.error('Error saving projects', e)
    return res.status(500).json({ ok:false, error:'Save failed' })
  }
})

app.get('/api/projects', (req, res) => {
  try {
    if (!fs.existsSync(EXPORT_FILE)) return res.json([])
    const raw = fs.readFileSync(EXPORT_FILE, 'utf8')
    const data = JSON.parse(raw || '[]')
    return res.json(Array.isArray(data) ? data : [])
  } catch (e) {
    console.error('Error reading projects', e)
    return res.json([])
  }
})

// Cloudinary sign (protected)
app.post('/api/cloudinary-sign', requireAdminMiddleware, (req, res) => {
  try {
    const { filename = '', folder = '' } = req.body || {}
    const key = process.env.CLOUDINARY_API_KEY
    const secret = process.env.CLOUDINARY_API_SECRET
    const cloud = process.env.CLOUDINARY_CLOUD_NAME
    if (!key || !secret || !cloud) return res.status(500).json({ ok:false, error:'Cloudinary keys not set' })
    const timestamp = Math.floor(Date.now() / 1000)
    let toSign = `timestamp=${timestamp}`
    if (folder) toSign += `&folder=${folder}`
    const signature = crypto.createHash('sha1').update(toSign + secret).digest('hex')
    return res.json({ ok:true, api_key: key, timestamp, signature, cloud_name: cloud })
  } catch (e) {
    console.error('cloudinary-sign', e)
    return res.status(500).json({ ok:false, error:'Signature failed' })
  }
})

// Test email endpoint
app.post('/api/send-test-email', async (req, res) => {
  try {
    const { toAdmin=true, toClientEmail=null } = req.body || {}
    if (toAdmin) {
      const obj = { name:'Test User', email:'test@example.com', phone:'+000', service:'Test', budget:'Test', message:'Test message', createdAt: new Date().toISOString() }
      const adminHtml = adminHtmlEmail(obj)
      await transporter.sendMail({
        from: process.env.FROM_EMAIL || (process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER),
        to: process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER,
        subject: '✉️ [Test] New request — NakArt Designs',
        html: adminHtml
      })
    }
    if (toClientEmail) {
      const clientHtml = confirmationHtmlEmail({ name:'Test User', service:'Test', message:'Test confirmation message' })
      await transporter.sendMail({
        from: process.env.FROM_EMAIL || (process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER),
        to: toClientEmail,
        subject: 'Thanks — I received your request',
        html: clientHtml
      })
    }
    return res.json({ ok:true })
  } catch (e) {
    console.error('send-test-email error', e)
    return res.status(500).json({ ok:false, error:'Failed to send test email' })
  }
})

app.get('/ping', (req, res) => res.send('pong'))

/* --------------------- Start server --------------------- */
app.listen(PORT, () => console.log(`Backend listening on http://localhost:${PORT}`))
