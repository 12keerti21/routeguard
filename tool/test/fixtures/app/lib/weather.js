const axios = require("axios")
const Cache = require("../models/cache")

// stores another API's answer unchecked, and carries a key in the URL
async function cacheForecast(city) {
	const res = await axios.get(`https://api.weather.example/v1?city=${city}&api_key=abcdef0123456789abcdef`)
	await Cache.create({ city, data: res.data })
}

// safe: validated before it is stored
async function safeForecast(city) {
	const res = await axios.get(`https://api.weather.example/v1?city=${city}`)
	const forecast = ForecastSchema.parse(res.data)
	await Cache.create({ city, forecast })
}

// runs code a third party returned
function runPlugin() {
	return axios.get("https://plugins.example.com/plugin.js").then(r => eval(r.data))
}

// plain http to a partner; local http is fine
const partnerFeed = () => fetch("http://partner.example.com/feed")
const health = () => fetch("http://localhost:4000/health")

module.exports = { cacheForecast, safeForecast, runPlugin, partnerFeed, health }
