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
// Helmet sets a bunch of safe headers
app.use(helmet())

// Parse cookies (to read authentication cookie)
app.use(cookieParser())

// CORS: allow specific origins for production with credentials support
const allowedOrigins = [
  'https://www.nakartdesigns.store',
  'https://nakartdesigns.store'
];

app.use(cors({
  origin: function (origin, callback) {
    // allow requests with no origin (like mobile apps or curl)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true, // 🔥 CRITICAL: allow cookies/auth headers
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

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

  if (smtpUser && smtpPass) {
    transporter = nodemailer.createTransport({
      host: smtpHost || 'smtp.gmail.com',
      port: Number(smtpPort) || 465,
      secure: (String(smtpSecure) === 'true') || true,
      auth: { user: smtpUser, pass: smtpPass }
    })
    return
  }

  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.GMAIL_USER, pass: process.env.GMAIL_APP_PASSWORD }
    })
    return
  }

  // No-auth transport (best-effort; may be rejected by many providers)
  transporter = nodemailer.createTransport({
    host: smtpHost || 'smtp.gmail.com',
    port: Number(smtpPort) || 465,
    secure: true
  })
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

function writeRequestsFile(list) {
  try { fs.writeFileSync(REQ_FILE, JSON.stringify(list || [], null, 2), 'utf8') } catch (e) { console.warn('writeRequestsFile err', e) }
}

function saveRequestToFile(obj) {
  const list = readRequestsFile()
  list.unshift(obj)
  writeRequestsFile(list)
}

/* --------------------- Email templates (stylish text header) --------------------- */
const COLORS = {
  burgundy: process.env.BRAND_BURGUNDY || '#B02A37',
  plum: process.env.BRAND_PLUM || '#502C5A',
  navy: process.env.BRAND_NAVY || '#1D1B4D',
  canvas: process.env.BRAND_CANVAS || '#F9F9F9'
}

function headerBlock(title, subtitle) {
  // Enhanced header with stylish NakArt Designs branding
  const logoUrl = process.env.LOGO_URL || ''
  const gradient = `linear-gradient(135deg, ${COLORS.plum} 0%, ${COLORS.burgundy} 100%)`
  const escapedTitle = safe(title)
  const escapedSubtitle = safe(subtitle || '')
  
  // Use logo if available, otherwise use stylish text-only design
  const headerContent = logoUrl 
    ? `<img src="${safe(logoUrl)}" alt="${escapedTitle}" style="height:48px; display:block; border-radius:8px; object-fit:contain" />`
    : `<div style="font-family: 'Georgia', 'Garamond', serif; font-weight:700; font-size:24px; letter-spacing:1.2px; text-transform:uppercase; color:white; line-height:1.2">${escapedTitle}</div>`
  
  return `
    <div style="background: ${gradient}; padding:28px 24px; color:white; text-align:center;">
      <div style="max-width:600px; margin:0 auto;">
        ${headerContent}
        ${escapedSubtitle ? `<div style="font-size:14px; opacity:0.95; margin-top:10px; font-weight:500; letter-spacing:0.3px">${escapedSubtitle}</div>` : ''}
      </div>
    </div>
  `
}

function wrapEmail(innerHtml, smallPrint='') {
  return `
    <div style="font-family: system-ui, -apple-system, 'Segoe UI', Roboto, Helvetica, Arial; background:${COLORS.canvas}; padding:20px;">
      <div style="max-width:700px; margin:0 auto; background:#fff; border-radius:12px; overflow:hidden; border:1px solid #ddd; box-shadow:0 2px 8px rgba(0,0,0,0.08)">
        ${innerHtml}
        <div style="padding:16px 20px; background:#fafbfc; border-top:1px solid #eee; color:#666; font-size:12px; text-align:center; line-height:1.4">${safe(smallPrint)}</div>
      </div>
    </div>
  `
}

function adminHtmlEmail({ name, email, phone, service, budget, message, createdAt }) {
  const header = headerBlock('NakArt Designs', 'New project inquiry')
  const body = `
    <div style="padding:24px;">
      <div style="background:#f9f9f9; padding:16px; border-radius:8px; margin-bottom:20px;">
        <table role="presentation" width="100%" style="border-collapse:collapse;">
          <tr style="border-bottom:1px solid #e0e0e0;">
            <td style="width:25%; color:#666; padding:8px 0; font-weight:600; font-size:13px">NAME</td>
            <td style="font-weight:700; padding:8px 0; font-size:15px; color:#222">${safe(name)}</td>
          </tr>
          <tr style="border-bottom:1px solid #e0e0e0;">
            <td style="color:#666; padding:8px 0; font-weight:600; font-size:13px">EMAIL</td>
            <td style="font-weight:500; padding:8px 0; font-size:14px"><a href="mailto:${safe(email)}" style="color:${COLORS.burgundy}; text-decoration:none">${safe(email)}</a></td>
          </tr>
          <tr style="border-bottom:1px solid #e0e0e0;">
            <td style="color:#666; padding:8px 0; font-weight:600; font-size:13px">PHONE</td>
            <td style="font-weight:500; padding:8px 0; font-size:14px">${safe(phone || 'Not provided')}</td>
          </tr>
          <tr style="border-bottom:1px solid #e0e0e0;">
            <td style="color:#666; padding:8px 0; font-weight:600; font-size:13px">SERVICE</td>
            <td style="font-weight:500; padding:8px 0; font-size:14px">${safe(service || 'General inquiry')}</td>
          </tr>
          <tr>
            <td style="color:#666; padding:8px 0; font-weight:600; font-size:13px">BUDGET</td>
            <td style="font-weight:500; padding:8px 0; font-size:14px">${safe(budget || 'Not specified')}</td>
          </tr>
        </table>
      </div>

      <div style="margin-bottom:16px;">
        <div style="font-weight:700; color:${COLORS.navy}; margin-bottom:10px; font-size:14px; text-transform:uppercase; letter-spacing:0.5px">Message</div>
        <div style="background:#f5f5f5; padding:14px; border-radius:8px; border-left:4px solid ${COLORS.burgundy}; white-space:pre-wrap; color:#333; font-size:14px; line-height:1.6">${safe(message)}</div>
      </div>

      <div style="margin-top:20px; display:flex; gap:10px; flex-wrap:wrap;">
        <a href="mailto:${safe(email)}" style="display:inline-block;padding:11px 18px;border-radius:6px;background:${COLORS.burgundy};color:white;text-decoration:none;font-weight:700;font-size:14px">Reply to Client</a>
        <a href="${safe(process.env.ADMIN_DASHBOARD_URL || (FRONTEND_ORIGIN + '/admin'))}" style="display:inline-block;padding:11px 18px;border-radius:6px;background:${COLORS.plum};color:white;text-decoration:none;font-weight:700;font-size:14px">Go to Admin Panel</a>
      </div>

      <div style="margin-top:16px; padding-top:16px; border-top:1px solid #eee; color:#888; font-size:12px;">Received: <strong>${safe(createdAt)}</strong></div>
    </div>
  `
  const small = `NakArt Designs • ${process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER || ''}`
  return wrapEmail(header + body, small)
}

function confirmationHtmlEmail({ name, service, message }) {
  const header = headerBlock('NakArt Designs', 'We received your request')
  const body = `
    <div style="padding:18px">
      <div style="font-size:15px; color:#222;">
        <p style="margin:0 0 10px">Hi ${safe(name || 'there')},</p>
        <p style="margin:0 0 12px; color:#444">Thanks for reaching out about <strong>${safe(service || 'your project')}</strong>. I’ll review this and reply within 48 hours on business days.</p>
        <div style="background:#fbfbfb; padding:12px; border-radius:8px; white-space:pre-wrap; color:#333;">${safe(message)}</div>
        <div style="margin-top:14px">
          <a href="mailto:${safe(process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER)}" style="display:inline-block;padding:10px 14px;border-radius:8px;background:${COLORS.burgundy};color:white;text-decoration:none;font-weight:700">Contact NakArt</a>
        </div>
        <p style="margin-top:12px;color:#666;font-size:13px">We aim to reply within 48 hours (business days).</p>
      </div>
    </div>
  `
  const small = `NakArt Designs • ${process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER || ''}`
  return wrapEmail(header + body, small)
}

function replyHtmlEmail({ adminName, replyText, originalRequest }) {
  const header = headerBlock('NakArt Designs', 'Response to your inquiry')
  const body = `
    <div style="padding:24px; color:#222;">
      <p style="margin:0 0 14px; font-size:16px; line-height:1.6">Hi <strong>${safe(originalRequest.name || 'there')}</strong>,</p>
      
      <div style="margin:14px 0 24px; line-height:1.7; font-size:15px; color:#333;">${safe(replyText).replace(/\n/g, '<br/>')}</div>

      <div style="margin-top:24px; padding-top:20px; border-top:2px solid #e0e0e0;">
        <div style="color:#666; font-size:13px; margin-bottom:8px;">Best regards,</div>
        <div style="font-weight:700; color:${COLORS.burgundy}; font-size:15px; margin-bottom:4px">${safe(adminName)}</div>
        <div style="font-size:14px;">
          <a href="mailto:${safe(process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER)}" style="color:${COLORS.navy}; text-decoration:none; font-weight:500">${safe(process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER)}</a>
        </div>
        <div style="font-size:13px; color:#888; margin-top:6px;">NakArt Designs • Creative Studio</div>
      </div>

      <div style="margin-top:24px; padding:16px; background:#f9f9f9; border-radius:8px;">
        <div style="font-size:12px; color:#666; margin-bottom:10px; font-weight:600; text-transform:uppercase; letter-spacing:0.4px">Your original message</div>
        <div style="background:#ffffff; padding:12px; border-radius:6px; border-left:4px solid ${COLORS.plum}; white-space:pre-wrap; color:#444; font-size:13px; line-height:1.6;">${safe(originalRequest.message || '')}</div>
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
  const adminHash = process.env.ADMIN_PASSWORD_HASH // bcrypt hash
  const adminPlain = process.env.ADMIN_PASSWORD // plaintext fallback

  if (!adminEmail) return { ok:false, error: 'Admin email not configured' }
  if (String(email).toLowerCase() !== String(adminEmail).toLowerCase()) return { ok:false, error:'Invalid email' }

  if (adminHash) {
    try {
      const match = await bcrypt.compare(String(password || ''), adminHash)
      return match ? { ok:true } : { ok:false, error:'Invalid password' }
    } catch (e) {
      return { ok:false, error:'Hash compare failed' }
    }
  }

  if (adminPlain) {
    return String(password) === String(adminPlain) ? { ok:true } : { ok:false, error:'Invalid password' }
  }

  return { ok:false, error:'No admin password configured on server' }
}

function requireAdminMiddleware(req, res, next) {
  // Accept Authorization Bearer or cookie
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

// Admin login - sets HttpOnly cookie (preferred)
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
    // return token in body for legacy clients (optional)
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

    // persist locally
    saveRequestToFile(obj)

    // Build admin email HTML (no file attachments)
    try {
      const adminEmail = process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER
      if (adminEmail) {
        const html = adminHtmlEmail(obj)
        await transporter.sendMail({
          from: process.env.FROM_EMAIL || adminEmail,
          to: adminEmail,
          subject: `✉️ New request from ${name} — ${service || 'General'}`,
          html
        })
      } else {
        console.warn('Admin email not configured; skipping admin notification')
      }
    } catch (e) {
      console.warn('Failed to send admin email', e && e.message ? e.message : e)
    }

    // optional client confirmation
    if (String(process.env.SEND_USER_CONFIRMATION || 'false') === 'true') {
      try {
        const html = confirmationHtmlEmail({ name, service, message })
        await transporter.sendMail({
          from: process.env.FROM_EMAIL || (process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER),
          to: email,
          subject: 'Thanks — I received your request',
          html
        })
      } catch (e) {
        console.warn('Failed to send confirmation to user:', e && e.message ? e.message : e)
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
      const info = await transporter.sendMail({
        from: process.env.FROM_EMAIL || (process.env.ADMIN_EMAIL || process.env.SMTP_USER || process.env.GMAIL_USER),
        to,
        subject,
        html
      })
      // record reply into requests.json
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
      console.error('Failed to send reply', e && e.message ? e.message : e)
      return res.status(500).json({ ok:false, error:'Failed to send reply' })
    }
  } catch (e) {
    console.error('respond-request error', e)
    return res.status(500).json({ ok:false, error:'Server error' })
  }
})

// Protected: export projects to server file (backup)
// Protected: save projects to backend (for cross-device sync)
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

// PUBLIC: get projects from backend (for cross-device sync - all pages need this)
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

// Protected: cloudinary sign for signed uploads
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

// Test email (developer) — helpful for checking templates
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

// Public ping
app.get('/ping', (req, res) => res.send('pong'))

/* --------------------- Start server --------------------- */
app.listen(PORT, () => console.log(`Backend listening on http://localhost:${PORT}`))
