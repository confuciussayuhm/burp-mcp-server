package burp.mcp.history

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.proxy.http.InterceptedRequest
import burp.api.montoya.proxy.http.InterceptedResponse
import burp.api.montoya.proxy.http.ProxyRequestHandler
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction
import burp.api.montoya.proxy.http.ProxyResponseHandler
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction

/**
 * A single proxy message's request and/or response as it stood after the other extensions' proxy
 * handlers ran, observed live as it passed through the proxy pipeline. Keyed by the proxy `messageId()`,
 * which is the same integer as [burp.api.montoya.proxy.ProxyHttpRequestResponse.id] in proxy history — so
 * a history tool can merge the capture back onto the matching history item by id.
 *
 * WHY THIS EXISTS: an extension can rewrite a body inside its own proxy handlers via `withBody()` +
 * `continueWith()`. That rewritten message is the one that actually flowed, but Montoya's proxy *history*
 * read-back collapses `request() == finalRequest()` and `response() == originalResponse()` to the
 * as-received bytes (montoya-api issue #127), so the rewrite is unreachable from `proxy().history()`.
 * Capturing it at the handler stage is the only way to surface it to the MCP history tools.
 *
 * Only the full raw message string is stored per side (headers and body are sliced from it on demand),
 * so each captured message costs one copy, not three.
 */
data class ProxyHandlerCapture(
    val messageId: Int,
    val requestRaw: String? = null,
    val responseRaw: String? = null,
)

/**
 * Bounded, in-memory store of [ProxyHandlerCapture] keyed by proxy messageId. FIFO-evicting: proxy
 * messageIds are monotonic, so dropping the oldest insertion drops the stalest message (which will never
 * receive a late response). Not persisted — captures are only meaningful within a live Burp session, and
 * they should never be written into the `.burp` project file.
 */
class ProxyHandlerCaptureStore(private val maxEntries: Int = DEFAULT_MAX_ENTRIES) {

    private val entries = object : LinkedHashMap<Int, ProxyHandlerCapture>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Int, ProxyHandlerCapture>): Boolean =
            size > maxEntries
    }

    fun recordRequest(messageId: Int, raw: String) {
        synchronized(entries) {
            val existing = entries[messageId]
            entries[messageId] = (existing ?: ProxyHandlerCapture(messageId)).copy(requestRaw = raw)
        }
    }

    fun recordResponse(messageId: Int, raw: String) {
        synchronized(entries) {
            val existing = entries[messageId]
            entries[messageId] = (existing ?: ProxyHandlerCapture(messageId)).copy(responseRaw = raw)
        }
    }

    fun get(messageId: Int): ProxyHandlerCapture? = synchronized(entries) { entries[messageId] }

    fun size(): Int = synchronized(entries) { entries.size }

    companion object {
        const val DEFAULT_MAX_ENTRIES = 3000
    }
}

/**
 * Registers read-only proxy request/response handlers that snapshot each request and response into a
 * [ProxyHandlerCaptureStore] at the last proxy stage. It never modifies traffic — every handler returns
 * `continueWith(...)` unchanged.
 *
 * REGISTRATION-ORDER CONTRACT (important):
 *  - Both sides are captured at the TO-BE-SENT stage, so a rewrite another extension makes at the RECEIVED
 *    stage is always seen, whatever the load order.
 *  - A rewrite made at the TO-BE-SENT stage is only seen if this extension's handler runs after it. Burp
 *    invokes handlers in extension LOAD order, so burp-mcp must be loaded BELOW that extension in Burp's
 *    Extensions list. Loaded above it, the capture matches the history copy and the tools fall back to it.
 */
class ProxyHandlerCapturer(
    private val api: MontoyaApi,
    private val store: ProxyHandlerCaptureStore,
) {

    private var requestRegistration: Registration? = null
    private var responseRegistration: Registration? = null

    private val requestHandler = object : ProxyRequestHandler {
        override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction =
            ProxyRequestReceivedAction.continueWith(interceptedRequest)

        override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
            runCatching {
                if (hasBody(interceptedRequest)) {
                    store.recordRequest(interceptedRequest.messageId(), interceptedRequest.toString())
                }
            }
            return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
        }
    }

    private val responseHandler = object : ProxyResponseHandler {
        override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction =
            ProxyResponseReceivedAction.continueWith(interceptedResponse)

        override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
            runCatching {
                if (hasBody(interceptedResponse)) {
                    store.recordResponse(interceptedResponse.messageId(), interceptedResponse.toString())
                }
            }
            return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
        }
    }

    fun register() {
        requestRegistration = api.proxy().registerRequestHandler(requestHandler)
        responseRegistration = api.proxy().registerResponseHandler(responseHandler)
    }

    fun deregister() {
        requestRegistration?.deregister()
        responseRegistration?.deregister()
        requestRegistration = null
        responseRegistration = null
    }
}

private fun hasBody(msg: HttpMessage): Boolean =
    runCatching { msg.bodyToString().isNotEmpty() }.getOrDefault(false)
