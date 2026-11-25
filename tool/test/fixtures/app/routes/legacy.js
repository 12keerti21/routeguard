const express = require("express")
const router = express.Router()
const Note = require("../models/note")

// shadow: the v1 copy of GET /api/notes/:id without its auth
router.get("/notes/:id", async (req, res) => res.send(await Note.findById(req.params.id)))

// a development endpoint still mounted
router.get("/dev/search", async (req, res) => res.send([]))

module.exports = router
