const express = require('express')
const jwt = require('jsonwebtoken')
const dotenv = require('dotenv')
const cors = require('cors')

dotenv.config()
const app = express()
app.use(express.json())
app.use(cors())

let users = [] // 簡單記憶體用戶資料

function generateAccessToken(user) {
  return jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}

function generateRefreshToken(user) {
  return jwt.sign(user, process.env.REFRESH_TOKEN_SECRET)
}

app.post('/register', (req, res) => {
  const { email, password } = req.body
  users.push({ email, password })
  res.json({ message: 'User registered' })
})

app.post('/login', (req, res) => {
  const { email, password } = req.body
  const user = users.find(u => u.email === email && u.password === password)
  if (!user) return res.status(403).json({ message: 'Invalid credentials' })

  const accessToken = generateAccessToken({ email })
  const refreshToken = generateRefreshToken({ email })
  res.json({ accessToken, refreshToken })
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

app.listen(process.env.PORT || 3000, () => {
  console.log('Auth API running')
})
