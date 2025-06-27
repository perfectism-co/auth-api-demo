import express from 'express'
import mongoose from 'mongoose'
import dotenv from 'dotenv'
import cors from 'cors'
import jwt from 'jsonwebtoken'
import bcrypt from 'bcrypt'

dotenv.config()

const app = express()
app.use(express.json())
app.use(cors())

// 🧠 MongoDB 連線
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ MongoDB connection error:', err))

// 🧩 Schema
const bookSchema = new mongoose.Schema({
  content: String,
  createdAt: { type: Date, default: Date.now }
})

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  books: [bookSchema]
})

const User = mongoose.model('User', userSchema)

// 🔐 JWT
function generateAccessToken(user) {
  return jwt.sign({ id: user._id }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user._id }, process.env.REFRESH_TOKEN_SECRET)
}

// 🔒 驗證 Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]
  if (!token) return res.sendStatus(401)

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    req.user = user
    next()
  })
}

// 🧾 refresh token 暫存
let refreshTokens = []

// 🧷 註冊
app.post('/register', async (req, res) => {
  const { email, password } = req.body
  const existing = await User.findOne({ email })
  if (existing) return res.status(400).json({ message: 'Email already registered' })

  const hashedPassword = await bcrypt.hash(password, 10)
  const user = new User({ email, password: hashedPassword })
  await user.save()

  res.json({ message: 'User registered' })
})

// 🔑 登入
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  const user = await User.findOne({ email })
  if (!user) return res.status(403).json({ message: 'Invalid credentials' })

  const match = await bcrypt.compare(password, user.password)
  if (!match) return res.status(403).json({ message: 'Invalid credentials' })

  const accessToken = generateAccessToken(user)
  const refreshToken = generateRefreshToken(user)
  refreshTokens.push(refreshToken)

  res.json({ accessToken, refreshToken })
})

// 🔁 Refresh Token
app.post('/refresh', (req, res) => {
  const { token } = req.body
  if (!token || !refreshTokens.includes(token)) return res.sendStatus(403)

  jwt.verify(token, process.env.REFRESH_TOKEN_SECRET, (err, user) => {
    if (err) return res.sendStatus(403)
    const accessToken = generateAccessToken({ _id: user.id })
    res.json({ accessToken })
  })
})

// 🚪 登出：撤銷 refresh token
app.post('/logout', (req, res) => {
  const { token } = req.body
  refreshTokens = refreshTokens.filter(t => t !== token)
  res.json({ message: 'Logged out successfully' })
})

// 👤 取得用戶資料
app.get('/me', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  res.json({
    id: user._id,
    email: user.email,
    books: user.books
  })
})

// 📘 新增書籍
app.post('/book', authenticateToken, async (req, res) => {
  const { content } = req.body
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  const book = { content }
  user.books.push(book)
  await user.save()

  res.json({ message: 'Book saved', book: user.books[user.books.length - 1] })
})

// ✏️ 修改書籍
app.put('/book/:bookId', authenticateToken, async (req, res) => {
  const { content } = req.body
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  const book = user.books.id(req.params.bookId)
  if (!book) return res.status(404).json({ message: 'Book not found' })

  book.content = content
  await user.save()

  res.json({ message: 'Book updated', book })
})

// 🗑️ 刪除書籍
app.delete('/book/:bookId', authenticateToken, async (req, res) => {
  const user = await User.findById(req.user.id)
  if (!user) return res.status(404).json({ message: 'User not found' })

  const originalLength = user.books.length
  user.books = user.books.filter(book => book._id.toString() !== req.params.bookId)

  if (user.books.length === originalLength) {
    return res.status(404).json({ message: 'Book not found' })
  }

  await user.save()
  res.json({ message: 'Book deleted' })
})

// 🚀 啟動伺服器
const PORT = process.env.PORT || 3000
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`)
})
