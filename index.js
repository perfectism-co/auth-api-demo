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

// 連線 MongoDB Atlas
mongoose.connect(process.env.MONGO_URL, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB Atlas'))
.catch(err => console.error('MongoDB connection error:', err))

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  refreshTokens: [String], // 可存多個 refresh token
  books: [{
    content: String,
    createdAt: { type: Date, default: Date.now }
  }]
})

const User = mongoose.model('User', userSchema)

// JWT 產生函式
function generateAccessToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, process.env.ACCESS_TOKEN_SECRET, { expiresIn: '15m' })
}

function generateRefreshToken(user) {
  return jwt.sign({ id: user._id, email: user.email }, process.env.REFRESH_TOKEN_SECRET)
}

// Middleware：驗證 accessToken
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

// 註冊
app.post('/register', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' })

  try {
    const existingUser = await User.findOne({ email })
    if (existingUser) return res.status(409).json({ message: 'User already exists' })

    const hashedPassword = await bcrypt.hash(password, 10)
    const user = new User({ email, password: hashedPassword, refreshTokens: [] })
    await user.save()
    res.json({ message: 'User registered' })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Server error' })
  }
})

// 登入
app.post('/login', async (req, res) => {
  const { email, password } = req.body
  if (!email || !password) return res.status(400).json({ message: 'Email and password required' })

  try {
    const user = await User.findOne({ email })
    if (!user) return res.status(403).json({ message: 'Invalid credentials' })

    const match = await bcrypt.compare(password, user.password)
    if (!match) return res.status(403).json({ message: 'Invalid credentials' })

    const accessToken = generateAccessToken(user)
    const refreshToken = generateRefreshToken(user)

    // 儲存 refreshToken 到資料庫
    user.refreshTokens.push(refreshToken)
    await user.save()

    res.json({ accessToken, refreshToken })
  } catch (err) {
    console.error(err)
    res.status(500).json({ message: 'Server error' })
  }
})

// 使用 refreshToken 取得新的 accessToken
app.post('/refresh', async (req, res) => {
  const { token } = req.body
  if (!token) return res.sendStatus(401)

  try {
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET)

    const user = await User.findById(payload.id)
    if (!user) return res.sendStatus(403)

    // 檢查 refreshToken 是否存在
    if (!user.refreshTokens.includes(token)) return res.sendStatus(403)

    const accessToken = generateAccessToken(user)
    res.json({ accessToken })
  } catch (err) {
    return res.sendStatus(403)
  }
})

// 登出 (撤銷 refresh token)
app.post('/logout', async (req, res) => {
  const { token } = req.body
  if (!token) return res.sendStatus(400)

  try {
    const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET)
    const user = await User.findById(payload.id)
    if (!user) return res.sendStatus(403)

    // 把該 refreshToken 從陣列移除
    user.refreshTokens = user.refreshTokens.filter(t => t !== token)
    await user.save()

    res.json({ message: 'Logged out successfully' })
  } catch (err) {
    res.sendStatus(403)
  }
})

// 取得用戶資料
app.get('/me', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-password -refreshTokens')
    if (!user) return res.sendStatus(404)
    res.json(user)
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

// 新增書本資料
app.post('/book', authenticateToken, async (req, res) => {
  const { content } = req.body
  if (!content) return res.status(400).json({ message: 'Content is required' })

  try {
    const user = await User.findById(req.user.id)
    if (!user) return res.sendStatus(404)

    user.books.push({ content, createdAt: new Date() })
    await user.save()

    res.json({ message: 'Book saved', book: user.books[user.books.length -1] })
  } catch (err) {
    res.status(500).json({ message: 'Server error' })
  }
})

const PORT = process.env.PORT || 3000
app.listen(PORT, () => console.log(`Server running on port ${PORT}`))
