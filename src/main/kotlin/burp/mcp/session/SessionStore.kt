package burp.mcp.session

import burp.api.montoya.persistence.PersistedObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Semaphore
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json

/**
 * One principal's captured, replayable session material.
 *
 * `cookie` / `authorization` are the raw header VALUES the real client sends on an authenticated
 * request; `extraHeaders` holds any additional session-bearing headers the operator named at capture
 * time (e.g. a bearer/session-token header the app carries outside `Authorization`). Together they are
 * everything `session_replay_as` needs to re-issue a captured request AS this principal.
 */
@Serializable
data class CapturedSession(
    val role: String,
    val host: String,
    val cookie: String?,
    val authorization: String?,
    val extraHeaders: Map<String, String>,
    val capturedAt: Long,
    val sourceId: Int?,
    val note: String?,
)

/**
 * A per-role keepalive: a script the burp-mcp runs on a timer, UNDER the role's [SessionStore.lockFor]
 * lock, to keep a rotating / idle-expiring session warm. The script is target-specific — what request
 * keeps the session alive, how to tell it is dead, how to roll the token or re-auth — and [language]
 * selects the embedded JSR-223 engine (default "groovy"). Persisted so warming survives a Burp restart.
 */
@Serializable
data class KeepAliveSpec(
    val role: String,
    val language: String,
    val script: String,
    val intervalMs: Long,
    val enabled: Boolean = true,
)

/**
 * A live browser session-injection binding (transient — not persisted; a browser is ephemeral).
 * Requests carrying header [headerName] == [token] to [host] have their session Cookie/Authorization
 * replaced with [role]'s CURRENT stored session, and the response rolled forward — so a browser and the
 * `session_replay_as` API share one source of truth instead of diverging. [token] is an opaque, neutral
 * identifier (carries no role or project name) that also tags that browser's traffic in Burp so the
 * operator can tell browsers apart. [serialize] gates the role's requests through the per-role semaphore
 * for a hard no-overlap guarantee against the rotate-and-wipe-on-stale failure mode.
 */
data class AttachSpec(
    val token: String,
    val role: String,
    val host: String,
    val headerName: String,
    val serialize: Boolean,
)

/**
 * Thread-safe store of per-role sessions — the burp-mcp analogue of the standalone token_broker's
 * role model, but living inside Burp where every session is already visible.
 *
 * Populated by the `session_capture` MCP tool, read by `session_get` / `session_replay_as` and the
 * "Sessions" UI tab. Also holds per-role keepalive specs (run by [KeepAliveManager]).
 *
 * When constructed with a [PersistedObject] (Burp's project-scoped extension data), sessions AND
 * keepalive specs are serialized into the `.burp` project file and reloaded on startup, so banked
 * roles and their warming survive extension reloads and Burp restarts.
 */
class SessionStore(private val persistence: PersistedObject? = null) {
    private val sessions = ConcurrentHashMap<String, CapturedSession>()
    private val keepAlives = ConcurrentHashMap<String, KeepAliveSpec>()

    /**
     * Per-role serialization gate (a fair binary semaphore). `session_replay_as`, the keepalive, and the
     * browser session-injector all acquire this so the read -> send -> roll-forward of a rotating
     * single-active token is never INTERLEAVED for one role. Interleaving lets the stored cookie fall
     * >= 2 rotations behind the server, and on a rotate-and-wipe-on-stale target,
     * a >= 2-rotation-stale request WIPES the session for every consumer. A semaphore, not a
     * ReentrantLock, because the injector acquires on Burp's request thread and releases on the response
     * thread. Transient — live process state, not persisted.
     */
    private val gates = ConcurrentHashMap<String, Semaphore>()
    private val attaches = ConcurrentHashMap<String, AttachSpec>()

    /** Last time a role's session was replayed or warmed (epoch ms). Transient; lets the keepalive
     *  skip a role the run is already keeping warm. */
    private val lastActivity = ConcurrentHashMap<String, Long>()

    init {
        if (persistence != null) load()
    }

    /** The role's serialization gate (fair binary semaphore, created on first use). */
    fun gateFor(role: String): Semaphore = gates.getOrPut(role) { Semaphore(1, true) }

    /** Run [action] holding the role's gate — for same-thread callers (session_replay_as, keepalive). */
    inline fun <T> withGate(role: String, action: () -> T): T {
        val gate = gateFor(role)
        gate.acquire()
        try {
            return action()
        } finally {
            gate.release()
        }
    }

    // Browser session-injection registry (transient — attaches are per live browser session).
    fun putAttach(a: AttachSpec) {
        attaches[a.token] = a
    }

    fun removeAttach(token: String): AttachSpec? = attaches.remove(token)

    fun attaches(): List<AttachSpec> = attaches.values.toList()

    fun touchActivity(role: String) {
        lastActivity[role] = System.currentTimeMillis()
    }

    fun lastActivity(role: String): Long = lastActivity[role] ?: 0L

    fun put(session: CapturedSession) {
        sessions[session.role] = session
        persist()
    }

    fun get(role: String): CapturedSession? = sessions[role]

    fun remove(role: String): CapturedSession? {
        keepAlives.remove(role)
        return sessions.remove(role)?.also { persist() }
    }

    fun clear() {
        sessions.clear()
        keepAlives.clear()
        persist()
    }

    fun size(): Int = sessions.size

    /** Snapshot of all captured sessions, most-recently-captured first. */
    fun list(): List<CapturedSession> = sessions.values.sortedByDescending { it.capturedAt }

    // -------------------------------------------------------------- keepalive registry
    fun putKeepAlive(spec: KeepAliveSpec) {
        keepAlives[spec.role] = spec
        persist()
    }

    fun removeKeepAlive(role: String): KeepAliveSpec? = keepAlives.remove(role)?.also { persist() }

    fun keepAlive(role: String): KeepAliveSpec? = keepAlives[role]

    fun keepAlives(): List<KeepAliveSpec> = keepAlives.values.toList()

    /** Load any sessions + keepalive specs persisted in a previous Burp session from the project store. */
    private fun load() {
        val p = persistence ?: return
        p.getString(KEY)?.takeIf { it.isNotBlank() }?.let { blob ->
            runCatching { JSON.decodeFromString(SESSION_LIST, blob) }.getOrNull()
                ?.forEach { sessions[it.role] = it }
        }
        p.getString(KA_KEY)?.takeIf { it.isNotBlank() }?.let { blob ->
            runCatching { JSON.decodeFromString(KA_LIST, blob) }.getOrNull()
                ?.forEach { keepAlives[it.role] = it }
        }
    }

    /** Rewrite the whole role set + keepalive set into the project store. No-op when unpersisted. */
    private fun persist() {
        val store = persistence ?: return
        store.setString(KEY, JSON.encodeToString(SESSION_LIST, sessions.values.toList()))
        store.setString(KA_KEY, JSON.encodeToString(KA_LIST, keepAlives.values.toList()))
    }

    private companion object {
        // Versioned so a future schema change can migrate instead of failing to parse.
        const val KEY = "sessionStore.v1"
        const val KA_KEY = "keepAliveStore.v1"
        val JSON = Json { explicitNulls = false; ignoreUnknownKeys = true }
        val SESSION_LIST = ListSerializer(CapturedSession.serializer())
        val KA_LIST = ListSerializer(KeepAliveSpec.serializer())
    }
}
