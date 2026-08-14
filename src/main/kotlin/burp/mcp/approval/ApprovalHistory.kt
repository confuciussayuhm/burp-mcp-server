package burp.mcp.approval


enum class HistoryResolution {
    // Resolved by the user in the Approvals card.
    APPROVED_MANUAL,
    APPROVED_HOST,
    APPROVED_HOST_PORT,
    APPROVED_ALWAYS,
    DENIED,
    CLEARED,

    // Let through by a rule, with no user interaction. These are what make the Approvals
    // card reflect traffic that is flowing rather than only traffic that was blocked.
    AUTO_RULE_DISABLED,
    AUTO_TARGET,
    AUTO_BURP_SCOPE,
    AUTO_CAPTURE,
    AUTO_ALWAYS_ALLOW;

    /** True when no user interaction produced this outcome. */
    val isAuto: Boolean
        get() = when (this) {
            AUTO_RULE_DISABLED, AUTO_TARGET, AUTO_BURP_SCOPE, AUTO_CAPTURE, AUTO_ALWAYS_ALLOW -> true
            else -> false
        }

    /** True when the request was let through, however it got there. */
    val isAllowed: Boolean
        get() = this != DENIED && this != CLEARED
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
 * Bounded ring buffer of approval outcomes — both the ones the user resolved by hand and the
 * ones a rule let straight through. In-memory only. Newest first.
 *
 * Auto-allowed outcomes are collapsed: repeat traffic to the same target under the same rule
 * bumps a hit count on the existing row in place rather than appending a new one. Without that
 * a single scan would push every manual decision out of the buffer in seconds; and bumping in
 * place rather than re-sorting keeps the row still while the user is reading it.
 */
class ApprovalHistory(private val capacity: Int = 256) {

    // ArrayList, not ArrayDeque: a repeat hit is an in-place replace at a known index, which a
    // deque cannot do. Index 0 is newest. Capacity is 256, so the O(n) insert at 0 is nothing.
    private val entries = ArrayList<HistoryEntry>()
    private val listeners = java.util.concurrent.CopyOnWriteArrayList<() -> Unit>()
    private var idCounter = 0L

    fun addListener(listener: () -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: () -> Unit) {
        listeners.remove(listener)
    }

    private fun fire() {
        listeners.forEach { it() }
    }

    /** Records a decision the user made on a queued approval. */
    fun record(approval: PendingApproval, resolution: HistoryResolution) {
        val entry = HistoryEntry(
            id = approval.id,
            kind = approval.kind,
            host = approval.host,
            port = approval.port,
            firstSeen = approval.firstSeen,
            resolvedAt = System.currentTimeMillis(),
            hitCount = approval.hitCount,
            resolution = resolution,
            preview = approval.preview
        )
        synchronized(entries) {
            entries.add(0, entry)
            trim()
        }
        fire()
    }

    /**
     * Records traffic that a rule let through. Collapses onto an existing row for the same
     * target + rule, so the list reads as "what is happening" rather than a raw request log.
     */
    fun recordAuto(kind: ApprovalKind, host: String?, port: Int?, reason: AllowReason, preview: String) {
        val resolution = reason.toResolution()
        val now = System.currentTimeMillis()
        synchronized(entries) {
            val index = entries.indexOfFirst {
                it.resolution == resolution &&
                    it.kind == kind &&
                    it.host.equals(host, ignoreCase = true) &&
                    it.port == port
            }
            if (index >= 0) {
                // Bump in place rather than floating to the front. Reordering on every repeat
                // request makes the list unreadable exactly when there is traffic to read —
                // the row you are looking at slides away under the cursor.
                val existing = entries[index]
                entries[index] = existing.copy(hitCount = existing.hitCount + 1, resolvedAt = now)
            } else {
                entries.add(
                    0,
                    HistoryEntry(
                        id = "auto-${++idCounter}",
                        kind = kind,
                        host = host,
                        port = port,
                        firstSeen = now,
                        resolvedAt = now,
                        hitCount = 1,
                        resolution = resolution,
                        preview = preview
                    )
                )
                trim()
            }
        }
        fire()
    }

    /** Caller must hold the `entries` lock. */
    private fun trim() {
        while (entries.size > capacity) entries.removeAt(entries.size - 1)
    }

    fun list(): List<HistoryEntry> = synchronized(entries) { entries.toList() }

    fun size(): Int = synchronized(entries) { entries.size }

    fun clear() {
        synchronized(entries) {
            if (entries.isEmpty()) return
            entries.clear()
        }
        fire()
    }
}
