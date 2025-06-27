// index.js
const express = require('express')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const cors = require('cors')
const { Pool } = require('pg')
const bcrypt = require('bcrypt')

dotenv.config()
const app = express()
app.use(express.json())
app.use(cors())

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
})

// 建立 users 表
pool.query(`
  CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
  )
`)

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
}

app.post('/register', async (req, res) => {
  const { email, password } = req.body
  try {
    const hashedPassword = await bcrypt.hash(password, 10)
    const result = await pool.query(
      'INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *',
      [email, hashedPassword]
    )
    res.json({ message: 'User registered', user: result.rows[0] })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'User registration failed' })
  }
})


app.post('/login', async (req, res) => {
  const { email, password } = req.body
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email])
    const user = result.rows[0]
    if (!user) return res.status(403).json({ message: 'Invalid credentials' })

    const match = await bcrypt.compare(password, user.password)
    if (!match) return res.status(403).json({ message: 'Invalid credentials' })

    const accessToken = generateAccessToken({ email })
    const refreshToken = generateRefreshToken({ email })
    res.json({ accessToken, refreshToken })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Login failed' })
  }
})

app.post('/refresh', (req, res) => {
  const { token } = req.body
  if (!token) return res.sendStatus(401)

  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    const accessToken = generateAccessToken({ email: user.email })
    res.json({ accessToken })
  })
})

app.get('/me', (req, res) => {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (!token) return res.sendStatus(401)

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    res.json({ email: user.email })
  })
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
