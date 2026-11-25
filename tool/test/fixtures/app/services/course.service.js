const Course = require("../models/course")

// leaks: takes the caller but never uses it
const getCourse = async (courseId, user) => {
	return Course.findById(courseId)
}

// scoped: the owner check happens two calls down
const findOwnedCourse = async (courseId, user) => Course.findOne({ _id: courseId, ownerOrgId: user.orgId })

const updateCourse = async ({ courseId, user, body }) => {
	const course = await loadForEdit(courseId, user)
	if (!course) return null
	return Course.updateOne({ _id: courseId }, body)
}

const loadForEdit = (courseId, user) => findOwnedCourse(courseId, user)

module.exports = { getCourse, updateCourse }
