package burp.mcp.approval

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

class PendingApprovalStore(private val maxPending: Int = 50) {

    private val approvals = ConcurrentHashMap<String, PendingApproval>()
    private val idCounter = AtomicLong(0)

    fun generateId(): String = "pa-${idCounter.incrementAndGet()}"

    fun put(approval: PendingApproval): Boolean {
        if (approvals.size >= maxPending && approvals[approval.id] == null) return false
        approvals[approval.id] = approval
        return true
    }

    fun get(id: String): PendingApproval? = approvals[id]

    fun remove(id: String): PendingApproval? = approvals.remove(id)

    fun findByTarget(kind: ApprovalKind, host: String?, port: Int?): PendingApproval? =
        approvals.values.firstOrNull {
            it.kind == kind &&
                it.host.equals(host, ignoreCase = true) &&
                it.port == port
        }

    fun list(): List<PendingApproval> = approvals.values.sortedBy { it.timestamp }

    fun size(): Int = approvals.size

    fun clear() {
        approvals.clear()
    }
}
