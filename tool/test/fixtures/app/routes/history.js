const express = require("express")
const router = express.Router()
const auth = require("../middleware/auth")
const { ENDPOINTS } = require("../lib/endpoints")
const { getHistory, setHistory } = require("../lib/historyStore")

const HistoryController = {
	// safe: the id only picks inside the caller's own history
	remove(req, res) {
		getHistory(req.user.id, (err, history) => {
			delete history[req.params.noteId]
			setHistory(req.user.id, history, () => res.end())
		})
	}
}

router.delete(ENDPOINTS.history, auth, (req, res) => HistoryController.remove(req, res))
router.put(ENDPOINTS.history, auth, HistoryController.remove)

// "otp" inside a word is not a one-time password
router.post(ENDPOINTS.flush, auth, (req, res) => res.end())

module.exports = router
