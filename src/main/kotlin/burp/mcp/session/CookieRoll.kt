package burp.mcp.session

/**
 * Cookie roll-forward helpers, shared by `session_replay_as` (ToolRegistry) and the per-role
 * [KeepAliveManager]. A target that ROTATES its session token on every response
 * invalidates the previous token after a tiny grace, so a role's stored `Cookie` must be
 * advanced from each response's `Set-Cookie` or the NEXT request 401s — or, worse, presents a stale
 * token the server treats as fixation and WIPES the whole session.
 */

/** Parse `name=value` from a `Set-Cookie` header value, ignoring the attributes after the first `;`. */
internal fun parseSetCookie(setCookie: String): Pair<String, String>? {
    val first = setCookie.substringBefore(';').trim()
    val eq = first.indexOf('=')
    if (eq <= 0) return null
    return first.substring(0, eq).trim() to first.substring(eq + 1).trim()
}

/**
 * Roll a role's stored `Cookie` header forward using the `Set-Cookie` values from a response. Existing
 * cookies are kept; rotated names are overwritten; a cookie set to empty / `deleted` is dropped.
 * Name-based merge (not Burp's global jar) so concurrent principals never collide — each role owns its
 * own cookie set.
 */
internal fun rollForwardCookies(current: String?, setCookies: List<String>): String {
    val jar = LinkedHashMap<String, String>()
    current?.split(";")?.forEach { part ->
        val eq = part.indexOf('=')
        if (eq > 0) jar[part.substring(0, eq).trim()] = part.substring(eq + 1).trim()
    }
    for (sc in setCookies) {
        parseSetCookie(sc)?.let { (name, value) ->
            if (value.isEmpty() || value.equals("deleted", ignoreCase = true)) jar.remove(name) else jar[name] = value
        }
    }
    return jar.entries.joinToString("; ") { "${it.key}=${it.value}" }
}
