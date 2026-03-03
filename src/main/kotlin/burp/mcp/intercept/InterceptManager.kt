package burp.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.proxy.http.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean

class InterceptManager(private val api: MontoyaApi) {

    val store = InterceptStore()
    private val enabled = AtomicBoolean(false)

    private val stateListeners = mutableListOf<(Boolean) -> Unit>()

    fun addStateListener(listener: (Boolean) -> Unit) {
        synchronized(stateListeners) { stateListeners.add(listener) }
    }

    private fun notifyStateListeners(enabled: Boolean) {
        synchronized(stateListeners) { stateListeners.toList() }.forEach { it(enabled) }
    }

    private var requestRegistration: Registration? = null
    private var responseRegistration: Registration? = null

    private val requestHandler = object : ProxyRequestHandler {
        override fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction =
            this@InterceptManager.handleRequestReceived(interceptedRequest)
        override fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction =
            this@InterceptManager.handleRequestToBeSent(interceptedRequest)
    }

    private val responseHandler = object : ProxyResponseHandler {
        override fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction =
            this@InterceptManager.handleResponseReceived(interceptedResponse)
        override fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction =
            this@InterceptManager.handleResponseToBeSent(interceptedResponse)
    }

    companion object {
        const val TIMEOUT_SECONDS = 120L
    }

    fun register() {
        requestRegistration = api.proxy().registerRequestHandler(requestHandler)
        responseRegistration = api.proxy().registerResponseHandler(responseHandler)
    }

    fun deregister() {
        disable()
        synchronized(stateListeners) { stateListeners.clear() }
        requestRegistration?.deregister()
        responseRegistration?.deregister()
        requestRegistration = null
        responseRegistration = null
    }

    fun enable() {
        enabled.set(true)
        api.logging().logToOutput("MCP intercept enabled")
        notifyStateListeners(true)
    }

    fun disable() {
        enabled.set(false)
        store.forwardAll()
        api.logging().logToOutput("MCP intercept disabled, all pending messages forwarded")
        notifyStateListeners(false)
    }

    fun isEnabled(): Boolean = enabled.get()

    private fun handleRequestReceived(interceptedRequest: InterceptedRequest): ProxyRequestReceivedAction {
        if (!enabled.get() || store.isFull()) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)
        }

        val future = CompletableFuture<MessageResolution>()
        val id = store.generateId()

        val method = try { interceptedRequest.method() } catch (_: Exception) { "UNKNOWN" }
        val url = try { interceptedRequest.url() } catch (_: Exception) { "unknown" }
        val host = try { interceptedRequest.httpService().host() } catch (_: Exception) { "unknown" }
        val port = try { interceptedRequest.httpService().port() } catch (_: Exception) { 0 }
        val secure = try { interceptedRequest.httpService().secure() } catch (_: Exception) { false }
        val listenerInterface = try { interceptedRequest.listenerInterface() } catch (_: Exception) { "unknown" }

        val pending = PendingRequest(
            id = id,
            timestamp = System.currentTimeMillis(),
            future = future,
            method = method,
            url = url,
            host = host,
            port = port,
            secure = secure,
            rawRequest = interceptedRequest.toString(),
            listenerInterface = listenerInterface
        )

        if (!store.add(pending)) {
            return ProxyRequestReceivedAction.continueWith(interceptedRequest)
        }

        api.logging().logToOutput("MCP intercepted request $id: $method $url")

        return try {
            when (val resolution = future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                is MessageResolution.Forward -> {
                    val request = if (resolution.modifiedRaw != null) {
                        HttpRequest.httpRequest(interceptedRequest.httpService(), resolution.modifiedRaw)
                    } else {
                        interceptedRequest
                    }
                    ProxyRequestReceivedAction.doNotIntercept(request)
                }
                is MessageResolution.Drop -> {
                    ProxyRequestReceivedAction.drop()
                }
            }
        } catch (_: TimeoutException) {
            store.removeMessage(id)
            api.logging().logToOutput("MCP intercept timeout for request $id, auto-forwarding")
            ProxyRequestReceivedAction.doNotIntercept(interceptedRequest)
        } catch (e: Exception) {
            store.removeMessage(id)
            api.logging().logToOutput("MCP intercept error for request $id: ${e.message}")
            ProxyRequestReceivedAction.doNotIntercept(interceptedRequest)
        }
    }

    private fun handleRequestToBeSent(interceptedRequest: InterceptedRequest): ProxyRequestToBeSentAction {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest)
    }

    private fun handleResponseReceived(interceptedResponse: InterceptedResponse): ProxyResponseReceivedAction {
        if (!enabled.get() || store.isFull()) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse)
        }

        val future = CompletableFuture<MessageResolution>()
        val id = store.generateId()

        val statusCode = try { interceptedResponse.statusCode().toInt() } catch (_: Exception) { 0 }
        val listenerInterface = try { interceptedResponse.listenerInterface() } catch (_: Exception) { "unknown" }
        val initiatingUrl = try { interceptedResponse.initiatingRequest().url() } catch (_: Exception) { "unknown" }
        val initiatingMethod = try { interceptedResponse.initiatingRequest().method() } catch (_: Exception) { "UNKNOWN" }

        val pending = PendingResponse(
            id = id,
            timestamp = System.currentTimeMillis(),
            future = future,
            statusCode = statusCode,
            rawResponse = interceptedResponse.toString(),
            initiatingRequestUrl = initiatingUrl,
            initiatingRequestMethod = initiatingMethod,
            listenerInterface = listenerInterface
        )

        if (!store.add(pending)) {
            return ProxyResponseReceivedAction.continueWith(interceptedResponse)
        }

        api.logging().logToOutput("MCP intercepted response $id: $statusCode for $initiatingMethod $initiatingUrl")

        return try {
            when (val resolution = future.get(TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                is MessageResolution.Forward -> {
                    val response = if (resolution.modifiedRaw != null) {
                        HttpResponse.httpResponse(resolution.modifiedRaw)
                    } else {
                        interceptedResponse
                    }
                    ProxyResponseReceivedAction.doNotIntercept(response)
                }
                is MessageResolution.Drop -> {
                    ProxyResponseReceivedAction.drop()
                }
            }
        } catch (_: TimeoutException) {
            store.removeMessage(id)
            api.logging().logToOutput("MCP intercept timeout for response $id, auto-forwarding")
            ProxyResponseReceivedAction.doNotIntercept(interceptedResponse)
        } catch (e: Exception) {
            store.removeMessage(id)
            api.logging().logToOutput("MCP intercept error for response $id: ${e.message}")
            ProxyResponseReceivedAction.doNotIntercept(interceptedResponse)
        }
    }

    private fun handleResponseToBeSent(interceptedResponse: InterceptedResponse): ProxyResponseToBeSentAction {
        return ProxyResponseToBeSentAction.continueWith(interceptedResponse)
    }
}
