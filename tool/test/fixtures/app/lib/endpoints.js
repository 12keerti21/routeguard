const PREFIX = "/api/v3"

const ENDPOINTS = Object.freeze({ history: "/history/:noteId", flush: "/admin/flushProjectToTpds" })

module.exports = { PREFIX, ENDPOINTS }
