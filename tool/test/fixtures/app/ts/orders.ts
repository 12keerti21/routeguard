import { Router } from "express"
import auth from "../middleware/auth.js"
import { Order, Hook } from "../models/index.js"

const router = Router()
const asyncHandler = (fn: any) => fn
const validateSessionMiddleware = (req: any, res: any, next: any) => next()
const api = { post: (...args: any[]) => args }

// safe: the admin check is in a wrapped inline middleware
router.get(
	"/metrics",
	auth,
	asyncHandler(async (req: any, res: any, next: any) => {
		if (!req.accountability?.admin) throw new Error("forbidden")
		next()
	}),
	(req: any, res: any) => res.json({ uptime: 1 })
)

// not a record id: a webhook names its provider
router.post("/webhooks/:provider", async (req: any, res: any) => {
	res.send(await Hook.findOne({ provider: req.params.provider }))
})

// BOLA behind a session guard
router.get("/:orderId", validateSessionMiddleware, async (req: any, res: any) => {
	res.json(await Order.findById(req.params.orderId))
})

// an HTTP client call, not a route
api.post("/graphql/system", { query: "{ orders }" })

export default router
