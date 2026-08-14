package burp.mcp.approval

/** Why a request was let through without asking the user. */
enum class AllowReason {
    /** The matching "Require approval for…" rule is switched off. */
    RULE_DISABLED,

    /** Host matched an entry in the approved-targets list. */
    APPROVED_TARGET,

    /** Host is in Burp's own Target → Scope. */
    BURP_SCOPE,

    /** Capture mode was on, so the target was approved and recorded on the spot. */
    CAPTURE_MODE,

    /** History type is marked always-allow. */
    ALWAYS_ALLOW;

    fun toResolution(): HistoryResolution = when (this) {
        RULE_DISABLED -> HistoryResolution.AUTO_RULE_DISABLED
        APPROVED_TARGET -> HistoryResolution.AUTO_TARGET
        BURP_SCOPE -> HistoryResolution.AUTO_BURP_SCOPE
        CAPTURE_MODE -> HistoryResolution.AUTO_CAPTURE
        ALWAYS_ALLOW -> HistoryResolution.AUTO_ALWAYS_ALLOW
    }
}

sealed class ApprovalDecision {
    data class Allow(val reason: AllowReason) : ApprovalDecision()
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
    /** When this target first got blocked. Kept separate from [lastSeen] so the recorded
     *  history entry says how long the client has been retrying, not just when it last tried. */
    val firstSeen: Long,
    val lastSeen: Long,
    val preview: String,
    val hitCount: Int
)
