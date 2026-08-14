package burp.mcp.approval

import java.util.concurrent.CopyOnWriteArrayList

class PendingApprovalManager {

    val store = PendingApprovalStore()
    val history = ApprovalHistory()

    private val listeners = CopyOnWriteArrayList<() -> Unit>()

    fun addListener(listener: () -> Unit) {
        listeners.add(listener)
    }

    fun removeListener(listener: () -> Unit) {
        listeners.remove(listener)
    }

    private fun fire() {
        listeners.forEach { it() }
    }

    fun enqueue(kind: ApprovalKind, host: String?, port: Int?, preview: String): PendingApproval {
        val (queued, evicted) = store.upsert(
            kind, host, port, preview, System.currentTimeMillis(), store::generateId
        )
        // An eviction is a decision the user never got to make, so it belongs in the activity
        // list rather than disappearing silently the way the old size cap did.
        evicted?.let { history.record(it, HistoryResolution.CLEARED) }
        fire()
        return queued
    }

    /**
     * Records traffic a rule let through. Also drops any queued approval for the same target —
     * once a request is flowing there is nothing left for the user to decide.
     */
    fun recordAllowed(kind: ApprovalKind, host: String?, port: Int?, reason: AllowReason, preview: String) {
        val stale = store.findByTarget(kind, host, port)
        if (stale != null) store.remove(stale.id)
        history.recordAuto(kind, host, port, reason, preview)
        if (stale != null) fire()
    }

    fun remove(id: String): PendingApproval? {
        val removed = store.remove(id)
        if (removed != null) fire()
        return removed
    }

    fun resolve(id: String, resolution: HistoryResolution): PendingApproval? {
        val removed = store.remove(id) ?: return null
        history.record(removed, resolution)
        fire()
        return removed
    }

    fun clearAll() {
        val all = store.list()
        if (all.isEmpty()) return
        store.clear()
        all.forEach { history.record(it, HistoryResolution.CLEARED) }
        fire()
    }
}
