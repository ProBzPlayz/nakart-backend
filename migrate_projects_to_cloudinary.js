// backend/migrate_projects_to_cloudinary.js
require('dotenv').config()
const fs = require('fs')
const path = require('path')
const Cloudinary = require('cloudinary').v2

const INPUT = path.join(__dirname, 'exported_projects.json')
const OUTPUT = path.join(__dirname, 'exported_projects.migrated.json')
const BACKUP = path.join(__dirname, 'exported_projects.backup.json')

const CLOUD = process.env.CLOUDINARY_CLOUD_NAME
const KEY = process.env.CLOUDINARY_API_KEY
const SECRET = process.env.CLOUDINARY_API_SECRET
const FOLDER = process.env.CLOUDINARY_MIGRATE_FOLDER || 'nakart_migrated'

if (!CLOUD || !KEY || !SECRET) {
  console.error('Set CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET in .env')
  process.exit(1)
}

Cloudinary.config({ cloud_name: CLOUD, api_key: KEY, api_secret: SECRET })

async function uploadDataUri(dataUri, publicIdHint) {
  // dataUri: data:<mime>;base64,<data>
  try {
    const res = await Cloudinary.uploader.upload(dataUri, { folder: FOLDER, public_id: publicIdHint, resource_type: 'image' })
    return res.secure_url
  } catch (e) {
    throw e
  }
}

async function main() {
  if (!fs.existsSync(INPUT)) {
    console.error('No exported projects file at', INPUT)
    process.exit(1)
  }

  const raw = JSON.parse(fs.readFileSync(INPUT,'utf8'))
  if (!Array.isArray(raw)) {
    console.error('Expected array in exported_projects.json')
    process.exit(1)
  }

  // backup
  fs.writeFileSync(BACKUP, JSON.stringify(raw, null, 2), 'utf8')
  console.log('Backup written to', BACKUP)

  let total = 0, migrated = 0, failed = 0
  for (let i = 0; i < raw.length; i++) {
    const p = raw[i]
    // hero
    if (p.hero && typeof p.hero === 'string' && p.hero.startsWith('data:')) {
      total++
      try {
        const publicId = `proj_${p.id || i}_hero_${Date.now()}`
        const url = await uploadDataUri(p.hero, publicId)
        p.hero = url
        migrated++
        console.log(`Uploaded hero for project ${p.id || p.title} -> ${url}`)
      } catch (e) {
        console.warn('Hero upload failed for', p.id || p.title, e.message || e)
        failed++
      }
    }
    // gallery
    if (Array.isArray(p.gallery)) {
      for (let gi = 0; gi < p.gallery.length; gi++) {
        const g = p.gallery[gi]
        if (typeof g === 'string' && g.startsWith('data:')) {
          total++
          try {
            const publicId = `proj_${p.id || i}_gallery_${gi}_${Date.now()}`
            const url = await uploadDataUri(g, publicId)
            p.gallery[gi] = url
            migrated++
            console.log(`Uploaded gallery image ${gi} for ${p.id || p.title}`)
          } catch (e) {
            console.warn('Gallery upload failed', p.id || p.title, gi, e.message || e)
            failed++
          }
        }
      }
    }
  }

  fs.writeFileSync(OUTPUT, JSON.stringify(raw, null, 2), 'utf8')
  console.log(`Done. total=${total} migrated=${migrated} failed=${failed}. Output: ${OUTPUT}`)
}

main().catch(e => { console.error(e); process.exit(1) })
