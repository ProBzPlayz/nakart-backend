// backend/routes/admin.js
import jwt from 'jsonwebtoken'

const JWT_SECRET = process.env.JWT_SECRET || 'replace_with_strong_secret'
const JWT_EXPIRES = process.env.JWT_EXPIRES || '7d'

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body
    if (!email || !password) return res.status(400).json({ ok: false, error: 'Missing credentials' })
    
    const adminEmail = process.env.ADMIN_EMAIL
    const adminHash = process.env.ADMIN_PASSWORD_HASH
    if (!adminEmail || !adminHash) return res.status(500).json({ ok: false, error: 'Admin not configured' })
    
    if (String(email).toLowerCase() !== String(adminEmail).toLowerCase()) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' })
    }
    
    const bcrypt = require('bcrypt')
    const match = await bcrypt.compare(String(password), adminHash)
    if (!match) {
      return res.status(401).json({ ok: false, error: 'Invalid credentials' })
    }

    const token = jwt.sign(
      { email: adminEmail, role: 'admin' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    )

    res.json({ ok: true, token })
  } catch (err) {
    console.error('Login error:', err)
    res.status(500).json({ ok: false, error: 'Login failed' })
  }
})
