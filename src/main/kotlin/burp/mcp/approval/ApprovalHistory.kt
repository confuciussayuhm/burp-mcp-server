package burp.mcp.approval

import java.util.ArrayDeque

enum class HistoryResolution {
    APPROVED_MANUAL,
    APPROVED_HOST,
    APPROVED_HOST_PORT,
    APPROVED_ALWAYS,
    DENIED,
    CLEARED
}

data class HistoryEntry(
    val id: String,
    val kind: ApprovalKind,
    val host: String?,
    val port: Int?,
    val firstSeen: Long,
    val resolvedAt: Long,
    val hitCount: Int,
    val resolution: HistoryResolution,
    val preview: String
)

/**
 * Bounded ring buffer of resolved approvals. In-memory only. Newest entries first.
 */
class ApprovalHistory(private val capacity: Int = 256) {

    private val entries = ArrayDeque<HistoryEntry>()
    private val listeners = mutableListOf<() -> Unit>()

    fun addListener(listener: () -> Unit) {
        synchronized(listeners) { listeners.add(listener) }
    }

    fun removeListener(listener: () -> Unit) {
        synchronized(listeners) { listeners.remove(listener) }
    }

    private fun fire() {
        synchronized(listeners) { listeners.toList() }.forEach { it() }
    }

    fun record(approval: PendingApproval, resolution: HistoryResolution) {
        val entry = HistoryEntry(
            id = approval.id,
            kind = approval.kind,
            host = approval.host,
            port = approval.port,
            firstSeen = approval.timestamp,
            resolvedAt = System.currentTimeMillis(),
            hitCount = approval.hitCount,
            resolution = resolution,
            preview = approval.preview
        )
        synchronized(entries) {
            entries.addFirst(entry)
            while (entries.size > capacity) entries.removeLast()
        }
        fire()
    }

    fun list(): List<HistoryEntry> = synchronized(entries) { entries.toList() }

    fun clear() {
        synchronized(entries) {
            if (entries.isEmpty()) return
            entries.clear()
        }
        fire()
    }
}
