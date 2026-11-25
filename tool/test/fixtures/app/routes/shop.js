const express = require("express")
const router = express.Router()
const security = require("../middleware/security")
const Basket = require("../models/basket")
const asyncHandler = fn => fn

// BOLA: the caller is read, but never used to scope the basket
function retrieveBasket() {
	return async (req, res) => {
		const basket = await Basket.findOne({ where: { id: req.params.id } })
		const user = security.authenticatedUsers.from(req)
		console.log(user)
		res.json(basket)
	}
}

// safe: scoped by the identity helper's result
function deleteCard() {
	return async (req, res) => {
		const data = security.authenticatedUsers.from(req)
		await Basket.destroy({ where: { id: req.params.id, UserId: data.id } })
		res.status(204).send()
	}
}

router.use("/basket/:id", security.isAuthorized())
router.get("/basket/:id", asyncHandler(retrieveBasket()))
router.delete("/cards/:id", security.isAuthorized(), asyncHandler(deleteCard()))

// safe: role checked inside the handler
router.delete("/baskets/:id", security.isAuthorized(), async (req, res) => {
	if (!requireAdmin(req, res)) return
	res.send(await Basket.destroy({ where: { id: req.params.id } }))
})

module.exports = router
