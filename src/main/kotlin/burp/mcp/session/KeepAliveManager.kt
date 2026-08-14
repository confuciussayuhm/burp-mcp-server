package burp.mcp.session

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.requests.HttpRequest
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit
import javax.script.ScriptEngine
import javax.script.ScriptEngineManager
import javax.script.SimpleBindings

/** The response surface a keepalive script sees. */
data class KeepAliveResponse(
    val status: Int,
    val location: String,
    val setCookies: List<String>,
    val headers: Map<String, String>,
    val body: String,
)

/**
 * Per-role context a keepalive script drives (bound as `ctx`). All HTTP goes through Burp so it is
 * proxied/logged like any other traffic. The [KeepAliveManager] already holds the role's lock while a
 * script runs, so a script is single-threaded w.r.t. its role and can safely read + update the store.
 */
class KeepAliveContext(
    private val api: MontoyaApi,
    private val store: SessionStore,
    @JvmField val role: String,
) {
    /** The role's current session (host/cookie/authorization/extraHeaders), or null if removed. */
    val session: CapturedSession? get() = store.get(role)
    val host: String? get() = session?.host

    /**
     * Send an authenticated request AS the role — the role's session Cookie/Authorization/extra headers
     * are injected first, then the script's [headers] (which may override). Sent to [path] on the role's
     * host over https:443. Redirects are NOT followed, so a 302 -> /auth/login is visible to the script.
     */
    @JvmOverloads
    fun send(method: String, path: String, headers: Map<String, String> = emptyMap(), body: String? = null): KeepAliveResponse {
        val s = session ?: return KeepAliveResponse(0, "", emptyList(), emptyMap(), "no session for role $role")
        val svc = HttpService.httpService(s.host, 443, true)
        var req = HttpRequest.httpRequest(svc, "$method $path HTTP/1.1\r\nHost: ${s.host}\r\n\r\n")
        s.cookie?.let { req = req.withUpdatedHeader("Cookie", it) }
        s.authorization?.let { req = req.withUpdatedHeader("Authorization", it) }
        s.extraHeaders.forEach { (k, v) -> req = req.withUpdatedHeader(k, v) }
        headers.forEach { (k, v) -> req = req.withUpdatedHeader(k, v) }
        body?.let { req = req.withBody(it) }
        val rr = api.http().sendRequest(req, RequestOptions.requestOptions().withRedirectionMode(RedirectionMode.NEVER))
        val resp = rr?.response() ?: return KeepAliveResponse(0, "", emptyList(), emptyMap(), "no response")
        val setCookies = resp.headers().filter { it.name().equals("Set-Cookie", ignoreCase = true) }.map { it.value() }
        val hdrs = resp.headers().associate { it.name() to it.value() }
        return KeepAliveResponse(resp.statusCode().toInt(), resp.headerValue("Location") ?: "", setCookies, hdrs, resp.bodyToString())
    }

    /** Roll the role's stored Cookie forward from a response's Set-Cookie values (the usual warm path). */
    fun rollForward(setCookies: List<String>) {
        val s = session ?: return
        val rolled = rollForwardCookies(s.cookie, setCookies)
        if (rolled.isNotEmpty() && rolled != s.cookie) store.put(s.copy(cookie = rolled))
    }

    /** Overwrite the role's stored Cookie header outright (e.g. after a re-auth mints a fresh session). */
    fun setCookie(cookieHeader: String) {
        val s = session ?: return
        store.put(s.copy(cookie = cookieHeader))
    }

    /** Mark this role's session dead: disable its keepalive (so the manager stops hammering a dead
     *  session) and log loudly so the operator re-seeds. */
    fun markDead(reason: String) {
        store.keepAlive(role)?.let { store.putKeepAlive(it.copy(enabled = false)) }
        api.logging().logToError("[keepalive:$role] SESSION DEAD -> re-seed required: $reason")
    }

    fun log(msg: String) = api.logging().logToOutput("[keepalive:$role] $msg")
}

/**
 * Runs each registered per-role keepalive script on a timer, UNDER the role's serialization lock, so
 * warming never overlaps a real `session_replay_as` for that role — which, on a rotate-and-wipe-on-stale
 * target, would trip the whole-session wipe. Scripts run via JSR-223 (default
 * engine "groovy") with a [KeepAliveContext] bound as `ctx`. A tick is SKIPPED for a role when the run
 * has replayed it within its interval (already warm) or when a real replay currently holds the lock.
 */
class KeepAliveManager(private val api: MontoyaApi, private val store: SessionStore) {
    private var exec: ScheduledExecutorService? = null
    private val engines = HashMap<String, ScriptEngine?>()
    private val engineManager = ScriptEngineManager(this::class.java.classLoader)

    fun start() {
        if (exec != null) return
        exec = Executors.newSingleThreadScheduledExecutor(ThreadFactory { r ->
            Thread(r, "mcp-session-keepalive").apply { isDaemon = true }
        }).also { it.scheduleWithFixedDelay({ runCatching { tick() } }, TICK_SEC, TICK_SEC, TimeUnit.SECONDS) }
        api.logging().logToOutput("MCP session keepalive manager started")
    }

    fun stop() {
        exec?.shutdownNow()
        exec = null
    }

    private fun tick() {
        val now = System.currentTimeMillis()
        for (spec in store.keepAlives()) {
            if (!spec.enabled) continue
            if (store.get(spec.role) == null) continue
            if (now - store.lastActivity(spec.role) < spec.intervalMs) continue // run is keeping it warm
            val gate = store.gateFor(spec.role)
            if (!gate.tryAcquire()) continue // a real replay / injected request holds the gate -> skip, retry
            try {
                runScript(spec)
                store.touchActivity(spec.role)
            } catch (t: Throwable) {
                api.logging().logToError("[keepalive:${spec.role}] script error: ${t.message}")
            } finally {
                gate.release()
            }
        }
    }

    private fun runScript(spec: KeepAliveSpec) {
        val engine = engines.getOrPut(spec.language.lowercase()) { engineManager.getEngineByName(spec.language) }
            ?: run {
                api.logging().logToError(
                    "[keepalive:${spec.role}] no JSR-223 engine for '${spec.language}' — is its jar on Burp's classpath?"
                )
                return
            }
        val bindings = SimpleBindings()
        bindings["ctx"] = KeepAliveContext(api, store, spec.role)
        engine.eval(spec.script, bindings)
    }

    private companion object {
        const val TICK_SEC = 20L
    }
}
