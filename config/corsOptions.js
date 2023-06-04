const corsOptions = {
  origin: (origin, cb) => {
    const allowedOrigins = [
      'http://localhost:8080',
      'http://127.0.0.1:8080',
      'http://localhost:3000',
      'http://localhost:18512', // for api docs
    ]
    allowedOrigins.includes(origin) || !origin
      ? cb(null, true)
      : cb(new Error('Not allowed by CORS'))
  },
  // 新增這項設定，才能讓前端接到 cookie
  credentials: true,
  optionsSuccessStatus: 200,
}

module.exports = corsOptions
