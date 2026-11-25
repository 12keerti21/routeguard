const express = require("express")
const router = express.Router()
const auth = require("../middleware/auth")
const courseService = require("../services/course.service")
const { Course, Review, Seat, Order } = require("../models")

router.get("/:courseId", auth, async (req, res) => {
	res.send(await courseService.getCourse(req.params.courseId, req.user))
})

router.put("/:courseId", auth, async (req, res) => {
	res.send(await courseService.updateCourse({ courseId: req.params.courseId, user: req.user, body: req.body }))
})

// safe: reads a public course to attach the caller's own review
router.post("/:courseId/reviews", auth, async (req, res) => {
	const course = await Course.findById(req.params.courseId)
	res.send(await Review.create({ course: course.id, author: req.user.id, text: req.body.text }))
})

// BOLA: creates the caller's record, but also empties someone else's course
router.post("/:courseId/checkout", auth, async (req, res) => {
	const course = await Course.findById(req.params.courseId)
	await Seat.destroy({ where: { courseId: req.params.courseId } })
	res.send(await Order.create({ course: course.id, buyer: req.user.id }))
})

module.exports = router
