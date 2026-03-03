package burp.mcp.intercept

import java.util.concurrent.CompletableFuture

sealed class MessageResolution {
    data class Forward(val modifiedRaw: String? = null) : MessageResolution()
    data object Drop : MessageResolution()
}

enum class MessageType { REQUEST, RESPONSE }

sealed class PendingMessage(
    val id: String,
    val type: MessageType,
    val timestamp: Long,
    val future: CompletableFuture<MessageResolution>
) {
    abstract val summary: String
}

class PendingRequest(
    id: String,
    timestamp: Long,
    future: CompletableFuture<MessageResolution>,
    val method: String,
    val url: String,
    val host: String,
    val port: Int,
    val secure: Boolean,
    val rawRequest: String,
    val listenerInterface: String
) : PendingMessage(id, MessageType.REQUEST, timestamp, future) {
    override val summary: String get() = "$method $url"
}

class PendingResponse(
    id: String,
    timestamp: Long,
    future: CompletableFuture<MessageResolution>,
    val statusCode: Int,
    val rawResponse: String,
    val initiatingRequestUrl: String,
    val initiatingRequestMethod: String,
    val listenerInterface: String
) : PendingMessage(id, MessageType.RESPONSE, timestamp, future) {
    override val summary: String get() = "$statusCode for $initiatingRequestMethod $initiatingRequestUrl"
}
