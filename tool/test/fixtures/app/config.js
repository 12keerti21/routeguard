const cors = require("cors")
const jwt = require("jsonwebtoken")

// CORS: any origin with credentials
const corsMiddleware = cors({ origin: (origin, cb) => cb(null, true), credentials: true })

// JWT: algorithm confusion, and a key in the code
const verify = token => jwt.verify(token, process.env.PUBLIC_KEY, { algorithms: ["RS256", "HS256"] })
const sign = payload => jwt.sign(payload, "s3cret")

// error leak: the stack goes to the client
const errorHandler = (err, req, res, next) => res.status(500).json({ message: err.message, stack: err.stack })

// safe: a fixed list of origins
const strictCors = cors({ origin: ["https://app.example.com"], credentials: true })

module.exports = { corsMiddleware, verify, sign, errorHandler, strictCors }
