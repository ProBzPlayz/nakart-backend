// backend/middleware/requireAdmin.js
const jwt = require('jsonwebtoken')

const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_strong_secret'

module.exports = function requireAdmin(req, res, next) {
  // Accept Bearer token OR cookie named 'nakart_admin_token'
  const auth = req.headers.authorization
  const cookieToken = req.cookies && req.cookies.nakart_admin_token
  const token = (auth && auth.startsWith('Bearer ') ? auth.split(' ')[1] : null) || cookieToken

  if (!token) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' })
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET)
    // require admin role
    if (!payload || payload.role !== 'admin') {
      return res.status(403).json({ ok: false, error: 'Forbidden' })
    }
    req.admin = payload
    return next()
  } catch (err) {
    console.warn('JWT verify failed:', err && err.message)
    return res.status(401).json({ ok: false, error: 'Invalid token' })
  }
}
