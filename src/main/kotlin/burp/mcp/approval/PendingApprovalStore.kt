package burp.mcp.approval

import java.util.concurrent.atomic.AtomicLong

/**
 * The queue of approvals waiting on the user.
 *
 * Guarded by a single lock rather than a ConcurrentHashMap: find-then-put has to be atomic, or
 * two tool calls racing on the same new target each create their own row and the card shows the
 * same host twice.
 */
class PendingApprovalStore(private val maxPending: Int = 50) {

    private val lock = Any()
    private val approvals = LinkedHashMap<String, PendingApproval>()
    private val idCounter = AtomicLong(0)

    fun generateId(): String = "pa-${idCounter.incrementAndGet()}"

    /**
     * Inserts or updates, evicting the oldest row when full.
     *
     * The cap used to reject the new entry, which meant the newest — the one the user is
     * actually waiting on — was the one that vanished, with nothing in the UI to say so.
     *
     * @return the evicted approval, if the insert pushed one out.
     */
    fun put(approval: PendingApproval): PendingApproval? {
        synchronized(lock) {
            approvals[approval.id] = approval
            if (approvals.size <= maxPending) return null
            val oldest = approvals.values.minByOrNull { it.firstSeen } ?: return null
            approvals.remove(oldest.id)
            return oldest
        }
    }

    fun get(id: String): PendingApproval? = synchronized(lock) { approvals[id] }

    fun remove(id: String): PendingApproval? = synchronized(lock) { approvals.remove(id) }

    fun findByTarget(kind: ApprovalKind, host: String?, port: Int?): PendingApproval? =
        synchronized(lock) { findByTargetLocked(kind, host, port) }

    /**
     * Bumps the hit count on an existing row for this target, or inserts a new one — atomically,
     * so concurrent tool calls for the same target cannot produce duplicate rows.
     *
     * @return the live row plus anything the size cap evicted to make room.
     */
    fun upsert(
        kind: ApprovalKind,
        host: String?,
        port: Int?,
        preview: String,
        now: Long,
        nextId: () -> String
    ): Pair<PendingApproval, PendingApproval?> {
        synchronized(lock) {
            val existing = findByTargetLocked(kind, host, port)
            val updated = existing?.copy(hitCount = existing.hitCount + 1, lastSeen = now)
                ?: PendingApproval(
                    id = nextId(),
                    kind = kind,
                    host = host,
                    port = port,
                    firstSeen = now,
                    lastSeen = now,
                    preview = preview,
                    hitCount = 1
                )
            approvals[updated.id] = updated
            var evicted: PendingApproval? = null
            if (approvals.size > maxPending) {
                approvals.values.minByOrNull { it.firstSeen }?.let {
                    if (it.id != updated.id) {
                        approvals.remove(it.id)
                        evicted = it
                    }
                }
            }
            return updated to evicted
        }
    }

    private fun findByTargetLocked(kind: ApprovalKind, host: String?, port: Int?): PendingApproval? =
        approvals.values.firstOrNull {
            it.kind == kind &&
                it.host.equals(host, ignoreCase = true) &&
                it.port == port
        }

    fun list(): List<PendingApproval> = synchronized(lock) { approvals.values.sortedBy { it.lastSeen } }

    fun size(): Int = synchronized(lock) { approvals.size }

    fun clear() {
        synchronized(lock) { approvals.clear() }
    }
}
