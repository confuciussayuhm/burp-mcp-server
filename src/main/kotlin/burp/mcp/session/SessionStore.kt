package burp.mcp.session

import burp.api.montoya.persistence.PersistedObject
import java.util.concurrent.ConcurrentHashMap
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
 * Thread-safe store of per-role sessions — the burp-mcp analogue of the standalone token_broker's
 * role model, but living inside Burp where every session is already visible.
 *
 * Populated by the `session_capture` MCP tool, read by `session_get` / `session_replay_as` and the
 * "Sessions" UI tab.
 *
 * When constructed with a [PersistedObject] (Burp's project-scoped extension data), the sessions are
 * serialized into the `.burp` project file and reloaded on startup, so banked roles survive extension
 * reloads and Burp restarts. This is deliberate and adds no exposure: the exact same credential
 * material (Cookie / Authorization header values, request bodies) is ALREADY persisted verbatim in the
 * project's proxy history, so an in-memory-only store bought no confidentiality while silently dropping
 * every banked role on restart — which broke replay-as after any Burp restart mid-engagement. The role
 * set is tiny (one entry per principal), so it is rewritten as a single JSON blob on each mutation
 * rather than incrementally.
 */
class SessionStore(private val persistence: PersistedObject? = null) {
    private val sessions = ConcurrentHashMap<String, CapturedSession>()

    init {
        if (persistence != null) load()
    }

    fun put(session: CapturedSession) {
        sessions[session.role] = session
        persist()
    }

    fun get(role: String): CapturedSession? = sessions[role]

    fun remove(role: String): CapturedSession? = sessions.remove(role)?.also { persist() }

    fun clear() {
        sessions.clear()
        persist()
    }

    fun size(): Int = sessions.size

    /** Snapshot of all captured sessions, most-recently-captured first. */
    fun list(): List<CapturedSession> = sessions.values.sortedByDescending { it.capturedAt }

    /** Load any sessions persisted in a previous Burp session from the project store. */
    private fun load() {
        val blob = persistence?.getString(KEY) ?: return
        if (blob.isBlank()) return
        runCatching { JSON.decodeFromString(LIST_SERIALIZER, blob) }
            .getOrNull()
            ?.forEach { sessions[it.role] = it }
    }

    /** Rewrite the whole role set into the project store. No-op when unpersisted. */
    private fun persist() {
        val store = persistence ?: return
        store.setString(KEY, JSON.encodeToString(LIST_SERIALIZER, sessions.values.toList()))
    }

    private companion object {
        // Versioned so a future schema change to CapturedSession can migrate instead of failing to parse.
        const val KEY = "sessionStore.v1"
        val JSON = Json { explicitNulls = false; ignoreUnknownKeys = true }
        val LIST_SERIALIZER = ListSerializer(CapturedSession.serializer())
    }
}
