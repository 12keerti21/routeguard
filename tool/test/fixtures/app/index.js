const express = require("express")
const auth = require("./middleware/auth")
const notes = require("./routes/notes")
const users = require("./routes/users")
const shop = require("./routes/shop")

const app = express()
app.use(express.json())
app.use("/api/notes", notes)
app.use("/api/users", users)
app.use("/api/private", auth, notes)
app.use("/rest", shop)

// a router built here and mounted under a prefix
const v2 = express.Router().use(users)
app.use("/v2", v2)
