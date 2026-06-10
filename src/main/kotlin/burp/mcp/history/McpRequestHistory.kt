package burp.mcp.history

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.persistence.PersistedList
import burp.api.montoya.persistence.PersistedObject
import java.util.ArrayDeque
import java.util.concurrent.atomic.AtomicInteger

/**
 * A single request/response issued by the MCP server's own send_http* tools.
 *
 * These requests go out via `api.http().sendRequest(...)`, which bypasses the proxy
 * and Repeater entirely — so they never appear in proxy history (the only history
 * Burp exposes to extensions) nor in the Repeater UI. This record is how we keep a
 * readable, byte-accurate log of what the MCP itself sent.
 */
data class McpRequestRecord(
    val id: Int,
    val timestamp: Long,
    val httpVersion: String,
    val request: HttpRequest,
    val response: HttpResponse?
)

/**
 * Log of every request issued by the MCP send tools. Unbounded — like Burp's own
 * Proxy history, nothing is discarded.
 *
 * When constructed with a [PersistedObject] (Burp's project-scoped extension data),
 * the log is persisted into the `.burp` project file and reloaded on startup, so it
 * survives extension reloads and Burp restarts. The records are mirrored into a set
 * of parallel [PersistedList]s; those lists are live views over the persisted data,
 * so appends are written incrementally rather than rewriting the whole log each time.
 *
 * Newest entries are returned first from [list].
 */
class McpRequestHistory(private val persistence: PersistedObject? = null) {

    private val entries = ArrayDeque<McpRequestRecord>()
    private val idCounter = AtomicInteger(0)

    // Parallel, identically-indexed persisted lists (oldest first). Null when no persistence.
    private var pRequestResponses: PersistedList<HttpRequestResponse>? = null
    private var pHasResponse: PersistedList<Boolean>? = null
    private var pTimestamps: PersistedList<Long>? = null
    private var pVersions: PersistedList<String>? = null

    init {
        if (persistence != null) initPersistence(persistence)
    }

    private fun initPersistence(data: PersistedObject) {
        // Create the lists on first run, then always work against the live persisted view.
        if (data.getHttpRequestResponseList(KEY_RR) == null) {
            data.setHttpRequestResponseList(KEY_RR, PersistedList.persistedHttpRequestResponseList())
            data.setBooleanList(KEY_HAS_RESP, PersistedList.persistedBooleanList())
            data.setLongList(KEY_TS, PersistedList.persistedLongList())
            data.setStringList(KEY_VER, PersistedList.persistedStringList())
        }
        pRequestResponses = data.getHttpRequestResponseList(KEY_RR)
        pHasResponse = data.getBooleanList(KEY_HAS_RESP)
        pTimestamps = data.getLongList(KEY_TS)
        pVersions = data.getStringList(KEY_VER)

        loadFromPersistence()
    }

    private fun loadFromPersistence() {
        val rr = pRequestResponses ?: return
        val hasResp = pHasResponse ?: return
        val ts = pTimestamps ?: return
        val ver = pVersions ?: return

        // Guard against any divergence between the parallel lists.
        val n = minOf(rr.size, hasResp.size, ts.size, ver.size)
        synchronized(entries) {
            for (i in 0 until n) {
                val pair = rr[i]
                val record = McpRequestRecord(
                    // IDs are positional and stable across restarts: the log is append-only.
                    id = i + 1,
                    timestamp = ts[i],
                    httpVersion = ver[i],
                    request = pair.request(),
                    response = if (hasResp[i]) pair.response() else null
                )
                entries.addFirst(record)
            }
            idCounter.set(n)
        }
    }

    fun record(request: HttpRequest, response: HttpResponse?, httpVersion: String): McpRequestRecord {
        synchronized(entries) {
            val record = McpRequestRecord(
                id = idCounter.incrementAndGet(),
                timestamp = System.currentTimeMillis(),
                httpVersion = httpVersion,
                request = request,
                response = response
            )
            entries.addFirst(record)

            // Mirror into the live persisted lists; appends persist incrementally.
            pRequestResponses?.let { rr ->
                val pair = HttpRequestResponse.httpRequestResponse(request, response ?: HttpResponse.httpResponse())
                rr.add(pair)
                pHasResponse?.add(response != null)
                pTimestamps?.add(record.timestamp)
                pVersions?.add(httpVersion)
            }
            return record
        }
    }

    fun list(): List<McpRequestRecord> = synchronized(entries) { entries.toList() }

    fun get(id: Int): McpRequestRecord? = synchronized(entries) { entries.firstOrNull { it.id == id } }

    companion object {
        private const val KEY_RR = "mcpRequestLog.requestResponses"
        private const val KEY_HAS_RESP = "mcpRequestLog.hasResponse"
        private const val KEY_TS = "mcpRequestLog.timestamps"
        private const val KEY_VER = "mcpRequestLog.httpVersions"
    }
}
