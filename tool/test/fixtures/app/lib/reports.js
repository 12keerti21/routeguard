const Report = require("../models/report")

// BOLA, reached through a "#lib/..." subpath import
const getReport = async (req, res) => {
	res.send(await Report.findById(req.params.id))
}

module.exports = { getReport }
