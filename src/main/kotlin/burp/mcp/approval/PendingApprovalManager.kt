package burp.mcp.approval

class PendingApprovalManager {

    val store = PendingApprovalStore()
    val history = ApprovalHistory()

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

    fun enqueue(kind: ApprovalKind, host: String?, port: Int?, preview: String): PendingApproval? {
        val existing = store.findByTarget(kind, host, port)
        val updated = if (existing != null) {
            existing.copy(hitCount = existing.hitCount + 1, timestamp = System.currentTimeMillis())
        } else {
            PendingApproval(
                id = store.generateId(),
                kind = kind,
                host = host,
                port = port,
                timestamp = System.currentTimeMillis(),
                preview = preview,
                hitCount = 1
            )
        }
        val added = store.put(updated)
        if (added) fire()
        return if (added) updated else null
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
