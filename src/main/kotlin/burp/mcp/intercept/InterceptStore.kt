package burp.mcp.intercept

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class InterceptStore(private val maxPendingMessages: Int = 50) {

    private val messages = ConcurrentHashMap<String, PendingMessage>()
    private val idCounter = AtomicLong(0)

    fun generateId(): String = "msg-${idCounter.incrementAndGet()}"

    fun add(message: PendingMessage): Boolean {
        if (messages.size >= maxPendingMessages) return false
        messages[message.id] = message
        return true
    }

    fun getMessage(id: String): PendingMessage? = messages[id]

    fun removeMessage(id: String): PendingMessage? = messages.remove(id)

    fun isFull(): Boolean = messages.size >= maxPendingMessages

    fun pendingRequests(): List<PendingRequest> =
        messages.values.filterIsInstance<PendingRequest>().sortedBy { it.timestamp }

    fun pendingResponses(): List<PendingResponse> =
        messages.values.filterIsInstance<PendingResponse>().sortedBy { it.timestamp }

    fun pendingMessages(): List<PendingMessage> =
        messages.values.sortedBy { it.timestamp }

    fun forwardAll() {
        val snapshot = messages.keys.toList()
        for (id in snapshot) {
            val message = messages.remove(id) ?: continue
            message.future.complete(MessageResolution.Forward())
        }
    }

    fun size(): Int = messages.size
}
