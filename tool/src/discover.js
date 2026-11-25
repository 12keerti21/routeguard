// Finds ids for route parameters by asking the app itself: /x/:fooId takes its id from GET /x,
// read as the owner and as the other user. An id only the owner sees is the owner's own record,
// which is what a fair object-level test needs. Each route gets ids from its own lists, so an
// address id never ends up in a basket route just because both call it :id.

const ID_KEYS = ["id", "_id", "uuid"]

const singular = word => word.replace(/ies$/i, "y").replace(/(s|x|z|ch|sh)es$/i, "$1").replace(/s$/i, "")
const PARAM = /^[:{](\w+)\}?(\([^)]*\))?$/

// the fields that may hold a value for :param, best first
function keysFor(param, collection) {
	const keys = [param]
	if (/id$/i.test(param) && param.length > 2) keys.push(...ID_KEYS)
	if (param === "id") keys.push(`${singular(collection)}Id`, `${singular(collection)}_id`)
	return [...new Set(keys)]
}

// every value under one of these keys, in any object inside the answer (lists, wrappers, pages)
function valuesFor(text, keys) {
	let body
	try {
		body = JSON.parse(text)
	} catch {
		return []
	}
	const found = []
	const visit = value => {
		if (Array.isArray(value)) value.forEach(visit)
		else if (value && typeof value === "object") {
			for (const key of keys) {
				const v = value[key]
				if (typeof v === "string" || typeof v === "number") found.push(String(v))
			}
			Object.values(value).forEach(visit)
		}
	}
	visit(body)
	return [...new Set(found)]
}

const OK = response => response && response.status >= 200 && response.status < 300

// known: ids given in the config by name, used wherever that name appears
export async function discoverParams({ routes, known, fetchAs }) {
	const cache = new Map()
	const get = async (who, url) => {
		const key = `${who} ${url}`
		if (!cache.has(key)) cache.set(key, await fetchAs(who, url))
		return cache.get(key)
	}
	const picked = new Map()
	const notes = []

	// the id for one parameter at one place in the tree: from the list at the path above it
	const pick = async (listUrl, param, collection) => {
		const memo = `${listUrl} ${param}`
		if (picked.has(memo)) return picked.get(memo)
		let choice = null
		const owner = await get("owner", listUrl)
		if (OK(owner)) {
			const keys = keysFor(param, collection)
			const ownerIds = valuesFor(owner.text, keys)
			if (ownerIds.length) {
				const other = await get("other", listUrl)
				const otherIds = new Set(OK(other) ? valuesFor(other.text, keys) : [])
				const own = ownerIds.find(id => !otherIds.has(id))
				choice = { param, value: own ?? ownerIds.at(0), from: `GET ${listUrl}`, ownerOnly: Boolean(own) }
				notes.push(choice)
			}
		}
		picked.set(memo, choice)
		return choice
	}

	const perRoute = new Map()
	for (const route of routes) {
		if (route.method !== "GET" || !/[:{]/.test(route.path) || /[*<]/.test(route.path)) continue
		const values = {}
		const sources = {}
		const segments = route.path.split("/")
		const filled = []
		for (const segment of segments) {
			const match = segment.match(PARAM)
			if (!match) {
				filled.push(segment)
				continue
			}
			const param = match[1]
			let value = known[param]
			if (value === undefined) {
				const collection = filled.at(-1)
				if (filled.length > 1 && collection && !PARAM.test(collection)) {
					const choice = await pick(filled.join("/"), param, collection)
					if (choice) {
						value = choice.value
						sources[param] = choice
					}
				}
			}
			if (value === undefined) break
			values[param] = value
			filled.push(encodeURIComponent(value))
		}
		perRoute.set(route.path, { values, sources })
	}
	return { perRoute, notes }
}
