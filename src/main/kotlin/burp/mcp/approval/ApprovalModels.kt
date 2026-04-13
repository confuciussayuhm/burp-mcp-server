package burp.mcp.approval

sealed class ApprovalDecision {
    data object Allow : ApprovalDecision()
    data class Deny(val reason: String, val pendingId: String?) : ApprovalDecision()
}

enum class ApprovalKind {
    HTTP_REQUEST,
    HTTP_HISTORY,
    WEBSOCKET_HISTORY
}

data class PendingApproval(
    val id: String,
    val kind: ApprovalKind,
    val host: String?,
    val port: Int?,
    val timestamp: Long,
    val preview: String,
    val hitCount: Int
)
