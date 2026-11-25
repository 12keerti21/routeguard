import { Router } from "express"
import orders from "./orders.js"

const api = Router()
api.use("/orders", orders)

export default api
