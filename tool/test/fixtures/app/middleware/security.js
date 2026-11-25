module.exports = {
	isAuthorized: () => (req, res, next) => next(),
	authenticatedUsers: { from: () => ({ id: 1 }) }
}
