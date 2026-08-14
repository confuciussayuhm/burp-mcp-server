package burp.mcp.session

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Annotations
import burp.api.montoya.core.HighlightColor
import burp.api.montoya.http.handler.HttpHandler
import burp.api.montoya.http.handler.HttpRequestToBeSent
import burp.api.montoya.http.handler.HttpResponseReceived
import burp.api.montoya.http.handler.RequestToBeSentAction
import burp.api.montoya.http.handler.ResponseReceivedAction
import burp.api.montoya.http.message.requests.HttpRequest
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ThreadFactory
import java.util.concurrent.TimeUnit

/**
 * Makes the burp-mcp [SessionStore] the single source of truth for a marked browser. On every request
 * to an attached role's host carrying the neutral marker header, it strips the browser's own cookies and
 * injects the role's CURRENT stored `Cookie`/`Authorization`, then rolls the store forward from the
 * response. So a Playwright browser and the `session_replay_as` API stop DIVERGING — the divergence that,
 * on a rotate-and-wipe-on-stale session, lets the two fall >= 2 rotations apart and wipes it. Both now
 * drive one coherent, Burp-managed session.
 *
 * When the attach is `serialize`, the role's requests are gated one-at-a-time through the per-role
 * semaphore (acquired here on Burp's request thread, released on the response thread), so browser + API +
 * keepalive never overlap on that role. A background reaper releases the gate for any request that never
 * gets a response (dropped connection), so a role can never deadlock.
 *
 * The marker header VALUE is an opaque token — it carries no role or project name — and also tags the
 * browser's traffic in Burp (annotation note) so the operator can tell concurrent browsers apart. The
 * marker header is stripped before the request leaves for the target; its neutral value is only a
 * belt-and-suspenders in case a strip is ever missed.
 */
class SessionInjector(private val api: MontoyaApi, private val store: SessionStore) : HttpHandler {

    private data class InFlight(val role: String, val gated: Boolean, val startedAt: Long)

    /** messageId -> in-flight managed request, so the response can roll forward + release the gate. */
    private val inFlight = ConcurrentHashMap<Int, InFlight>()

    private val reaper: ScheduledExecutorService =
        Executors.newSingleThreadScheduledExecutor(ThreadFactory { r ->
            Thread(r, "mcp-injector-reaper").apply { isDaemon = true }
        })

    fun start() {
        reaper.scheduleWithFixedDelay({ runCatching { reapStale() } }, REAP_SEC, REAP_SEC, TimeUnit.SECONDS)
    }

    fun stop() {
        reaper.shutdownNow()
    }

    override fun handleHttpRequestToBeSent(req: HttpRequestToBeSent): RequestToBeSentAction {
        val attach = matchAttach(req) ?: return RequestToBeSentAction.continueWith(req)
        val session = store.get(attach.role)
            ?: return RequestToBeSentAction.continueWith(req.withRemovedHeader(attach.headerName))

        if (attach.serialize) {
            store.gateFor(attach.role).acquire()
            inFlight[req.messageId()] = InFlight(attach.role, gated = true, startedAt = System.currentTimeMillis())
        } else {
            inFlight[req.messageId()] = InFlight(attach.role, gated = false, startedAt = System.currentTimeMillis())
        }

        var out: HttpRequest = req.withRemovedHeader(attach.headerName)
        session.cookie?.let { out = out.withUpdatedHeader("Cookie", it) }
        session.authorization?.let { out = out.withUpdatedHeader("Authorization", it) }
        session.extraHeaders.forEach { (k, v) -> out = out.withUpdatedHeader(k, v) }
        store.touchActivity(attach.role)

        return RequestToBeSentAction.continueWith(out, Annotations.annotations(attach.token, HighlightColor.CYAN))
    }

    override fun handleHttpResponseReceived(resp: HttpResponseReceived): ResponseReceivedAction {
        val flight = inFlight.remove(resp.messageId()) ?: return ResponseReceivedAction.continueWith(resp)
        try {
            val session = store.get(flight.role)
            if (session != null) {
                val setCookies = resp.headers()
                    .filter { it.name().equals("Set-Cookie", ignoreCase = true) }
                    .map { it.value() }
                if (setCookies.isNotEmpty()) {
                    val rolled = rollForwardCookies(session.cookie, setCookies)
                    if (rolled.isNotEmpty() && rolled != session.cookie) store.put(session.copy(cookie = rolled))
                }
                store.touchActivity(flight.role)
            }
        } finally {
            if (flight.gated) runCatching { store.gateFor(flight.role).release() }
        }
        return ResponseReceivedAction.continueWith(resp)
    }

    /** The first attach whose neutral marker header matches this request AND whose host matches. */
    private fun matchAttach(req: HttpRequestToBeSent): AttachSpec? {
        val host = req.httpService().host()
        for (a in store.attaches()) {
            if (!host.equals(a.host, ignoreCase = true)) continue
            if (req.headerValue(a.headerName) == a.token) return a
        }
        return null
    }

    /** Release the gate for any request that never got a response (dropped connection) so a serialized
     *  role can never deadlock. Cutoff is well beyond any real request. */
    private fun reapStale() {
        val cutoff = System.currentTimeMillis() - STALE_MS
        for ((id, f) in inFlight) {
            if (f.startedAt < cutoff && inFlight.remove(id, f)) {
                if (f.gated) runCatching { store.gateFor(f.role).release() }
                api.logging().logToError("[injector] reaped stale in-flight request $id (role ${f.role}) — gate released")
            }
        }
    }

    private companion object {
        const val REAP_SEC = 15L
        const val STALE_MS = 60_000L
    }
}
