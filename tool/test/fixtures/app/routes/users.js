const express = require("express")
const _ = require("lodash")
const router = express.Router()
const auth = require("../middleware/auth")
const User = require("../models/user")

// mass assignment: the whole body
router.post("/", async (req, res) => {
	const user = new User(req.body)
	res.send(await user.save())
})

// mass assignment: a privileged field by name
router.post("/signup", async (req, res) => {
	res.send(await User.create({ name: req.body.name, isAdmin: req.body.isAdmin }))
})

// safe: only allowed fields
router.post("/invite", async (req, res) => {
	res.send(await User.create(_.pick(req.body, ["name", "email"])))
})

// BFLA: operator function without a role check
router.get("/admin/stats", auth, async (req, res) => {
	res.send(await User.countDocuments())
})

module.exports = router
