const express = require("express")
const router = express.Router()
const auth = require("../middleware/auth")
const admin = require("../middleware/admin")
const Note = require("../models/note")
const { getReport } = require("#lib/reports.js")

// BOLA: any signed-in user reads any note
router.get("/:id", auth, async (req, res) => {
	res.send(await Note.findById(req.params.id))
})

// safe: scoped to the caller
router.get("/mine/:id", auth, async (req, res) => {
	const { id } = req.params
	res.send(await Note.findOne({ _id: id, owner: req.user.id }))
})

// safe: admins may delete any note
router.delete("/:id", [auth, admin], async (req, res) => {
	res.send(await Note.findByIdAndDelete(req.params.id))
})

// BFLA: shared record written by any signed-in user
router.post("/pinned", auth, async (req, res) => {
	res.send(await Note.create({ text: req.body.text }))
})

// safe: the note belongs to the caller
router.post("/", auth, async (req, res) => {
	res.send(await Note.create({ text: req.body.text, owner: req.user.id }))
})

// safe: public read without an id lookup by the caller
router.get("/", async (req, res) => {
	res.send(await Note.find())
})

router.get("/reports/:id", auth, getReport)

module.exports = router
