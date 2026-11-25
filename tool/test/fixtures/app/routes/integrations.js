const express = require("express")
const axios = require("axios")
const rateLimit = require("express-rate-limit")
const router = express.Router()
const auth = require("../middleware/auth")
const User = require("../models/user")

// SSRF: the client picks the URL
router.post("/preview", auth, async (req, res) => {
	res.send((await axios.get(req.body.url)).data)
})

// SSRF, milder: the client fills a parameter of a fixed host
router.get("/weather", async (req, res) => {
	const url = `https://api.weather.example/v1/now?city=${req.query.city}&key=` + process.env.KEY
	res.send(await fetch(url))
})

// safe: the host is checked first
router.post("/webhook-test", auth, async (req, res) => {
	const url = req.body.url
	if (!isAllowedHost(url)) return res.status(400).end()
	res.send((await axios.post(url)).status)
})

// no limiter on a password check
router.post("/login", async (req, res) => res.send(await User.findOne({ email: req.body.email }).select("_id")))

// safe: limited
router.post("/login-limited", rateLimit({ max: 5 }), async (req, res) => res.end())

// a code check behind a session is still guessable
router.post("/otp-verify", auth, async (req, res) => res.end())

// safe: a signed-in user setting a new password
router.post("/change-password", auth, async (req, res) => res.end())

// data exposure: the whole user record
router.get("/people/:id", auth, (req, res) => {
	User.findById(req.params.id).then(user => res.json({ user }))
})

// safe: selected fields
router.get("/people/:id/card", auth, async (req, res) => {
	const user = await User.findById(req.params.id).select("name avatar")
	res.json(user)
})

// API6: a checkout with nothing against bots
router.post("/checkout", auth, async (req, res) => res.end())

// safe: redemption is limited
router.post("/redeem", auth, rateLimit({ max: 3 }), async (req, res) => res.end())

// safe: a catalogue, not a flow
router.post("/books", auth, async (req, res) => res.end())

// safe: the token gates it
router.post("/invites/:token/accept", async (req, res) => res.end())

// validate(schemas.login) validates; it is not a login check
router.post("/signin", validate(schemas.login), async (req, res) => res.end())

// limited by app.use("/int/limited", authLimiter) in index.js
router.post("/limited/login", async (req, res) => res.end())

module.exports = router
