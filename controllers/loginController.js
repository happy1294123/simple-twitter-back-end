const jwt = require('jsonwebtoken')
const { v4: uuidv4 } = require('uuid')
const { User, Admin } = require('../models')

const makeRefreshToken = (account) => {
  return jwt.sign(
    { account, type: 'refresh' },
    process.env.REFRESH_TOKEN_SECRET,
    { expiresIn: '1d' }
  )
}

const makeAccessToken = (account) => {
  return jwt.sign(
    { account, type: 'access' },
    process.env.ACCESS_TOKEN_SECRET,
    { expiresIn: '30s' }
  )
}

const setCookie = (res, refreshToken) => {
  res.cookie('jwt', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'None',
    maxAge: 24 * 60 * 60 * 1000,
  })
}

const authToken = async (req, res) => {
  // make refresh token && save in cookie
  let user
  user = await User.findOne({ where: { account: req.user.account } })
  if (!user) {
    user = await Admin.findOne({ where: { account: req.user.account } })
  }
  const refreshToken = makeRefreshToken(req.user.account)
  user.refreshToken = refreshToken
  await user.save()
  setCookie(res, refreshToken)

  // make access token && send by json
  const accessToken = makeAccessToken(req.user.account)
  res.json({
    id: user.id,
    account: user.account,
    name: user.name,
    email: user.email,
    role: user.role,
    avatar: user.avatar,
    accessToken,
  })
}

const handleLogout = async (req, res) => {
  const refreshToken = req.cookies.jwt
  if (refreshToken) {
    let user
    user = await User.findOne({ where: { refreshToken } })
    if (!user) {
      user = await Admin.findOne({ where: { refreshToken } })
    }
    user.refreshToken = null
    await user.save()
  }
  res.clearCookie('jwt', { httpOnly: true, sameSite: 'None', secure: true })
  res.sendStatus(204)
}

const googleAuth = async (req, res) => {
  const payLoad = jwt.decode(req.body.id_token)
  let user
  try {
    ;[user, _] = await User.findOrCreate({
      where: {
        googleId: payLoad.sub,
      },
      defaults: {
        account: payLoad.email,
        name: payLoad.name,
        password: uuidv4(),
        email: payLoad.email,
        avatar: payLoad.picture,
        googleId: payLoad.sub,
      },
    })
  } catch (err) {
    console.log(err)
    return res.status(507).json({ message: '資料庫請求錯誤' })
  }

  const refreshToken = makeRefreshToken(user.account)
  user.refreshToken = refreshToken
  await user.save()
  setCookie(res, refreshToken)
  const accessToken = makeAccessToken(user.account)
  res.json({
    id: user.id,
    account: user.account,
    name: user.name,
    email: user.email,
    role: user.role,
    avatar: user.avatar,
    accessToken,
  })
}

module.exports = { authToken, handleLogout, googleAuth }
