package burp.mcp.approval

import burp.api.montoya.MontoyaApi
import burp.mcp.McpConfig
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The single place that decides whether MCP may touch a target or a history store.
 *
 * It used to live as private helpers inside ToolRegistry, which meant the UI had no way to ask
 * "would this still be blocked?" — so a pending approval stayed queued forever after the user
 * had approved the host by some other route. Everything that needs the answer now goes through
 * here, and every answer is recorded so the Approvals card reflects live traffic rather than
 * only the traffic that got blocked.
 */
class ApprovalPolicy(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val approvals: PendingApprovalManager
) {

    private val reconciling = AtomicBoolean(false)

    // --- Pure predicates -------------------------------------------------------------------

    /** @param port null when the caller only knows the host (e.g. a stored session). */
    fun matchesApprovedTarget(hostname: String, port: Int?): Boolean =
        config.getAutoApproveTargetsList().any { approved ->
            when {
                approved.equals(hostname, ignoreCase = true) -> true
                port != null && approved.equals("$hostname:$port", ignoreCase = true) -> true
                approved.startsWith("*.") -> {
                    val domain = approved.substring(2)
                    hostname.endsWith(".$domain", ignoreCase = true) || hostname.equals(domain, ignoreCase = true)
                }
                else -> false
            }
        }

    fun isInBurpScope(hostname: String, port: Int?, secure: Boolean): Boolean {
        val primary = if (secure) "https" else "http"
        val other = if (secure) "http" else "https"
        val candidates = buildList {
            if (port != null) {
                add("$primary://$hostname:$port/")
                add("$other://$hostname:$port/")
            }
            add("$primary://$hostname/")
            add("$other://$hostname/")
        }
        for (url in candidates) {
            try {
                if (api.scope().isInScope(url)) return true
            } catch (e: Exception) {
                api.logging().logToError("MCP scope check failed for $url: ${e.message}")
            }
        }
        return false
    }

    /**
     * Why this target would be let through right now, or null if it still needs approval.
     * Side-effect free — safe to call from the UI and from [reconcilePending].
     */
    fun allowReasonForHttpRequest(hostname: String, port: Int?, secure: Boolean): AllowReason? = when {
        !config.requireHttpRequestApproval -> AllowReason.RULE_DISABLED
        matchesApprovedTarget(hostname, port) -> AllowReason.APPROVED_TARGET
        config.useBurpScopeForApproval && isInBurpScope(hostname, port, secure) -> AllowReason.BURP_SCOPE
        config.autoApproveAllNewTargets -> AllowReason.CAPTURE_MODE
        else -> null
    }

    /** Side-effect free. */
    fun allowReasonForHistory(kind: ApprovalKind): AllowReason? = when {
        !config.requireHistoryAccessApproval -> AllowReason.RULE_DISABLED
        config.autoApproveAllNewTargets -> AllowReason.CAPTURE_MODE
        kind == ApprovalKind.HTTP_HISTORY && config.alwaysAllowHttpHistory -> AllowReason.ALWAYS_ALLOW
        kind == ApprovalKind.WEBSOCKET_HISTORY && config.alwaysAllowWebSocketHistory -> AllowReason.ALWAYS_ALLOW
        else -> null
    }

    // --- Decisions (these record, and may queue) --------------------------------------------

    /**
     * Gate for any tool about to put bytes on the wire. Every such tool must call this with the
     * service it will actually use — after retargeting, not the one the request was captured on.
     */
    fun checkHttpRequest(hostname: String, port: Int?, secure: Boolean, preview: String): ApprovalDecision {
        val reason = allowReasonForHttpRequest(hostname, port, secure)
        if (reason != null) {
            // Capture mode exists to build the approved list as you go.
            if (reason == AllowReason.CAPTURE_MODE) {
                config.addAutoApproveTarget(if (port != null) "$hostname:$port" else hostname)
            }
            approvals.recordAllowed(ApprovalKind.HTTP_REQUEST, hostname, port, reason, preview)
            return ApprovalDecision.Allow(reason)
        }

        val pending = approvals.enqueue(ApprovalKind.HTTP_REQUEST, hostname, port, preview)
        val target = if (port != null) "$hostname:$port" else hostname
        val message = buildString {
            append("Target `$target` is not approved for MCP access. ")
            append("A pending approval has been queued (id ${pending.id}). ")
            append("Approve it by: (1) opening Burp → MCP → Server → Approvals and clicking Approve, ")
            append("(2) right-clicking the host in Proxy History → \"MCP: Auto-approve target\", ")
            append("(3) adding the host to Burp's Target → Scope, ")
            append("or (4) adding `$hostname` (or `*.$hostname`) to the approved targets list. ")
            append("Then retry the tool call.")
        }
        return ApprovalDecision.Deny(message, pending.id)
    }

    fun checkHistory(historyType: String): ApprovalDecision {
        val kind = if (historyType == "WebSocket") ApprovalKind.WEBSOCKET_HISTORY else ApprovalKind.HTTP_HISTORY
        val preview = "An MCP client is requesting access to your Burp Suite $historyType history. " +
            "This may include sensitive data from previous web sessions."

        val reason = allowReasonForHistory(kind)
        if (reason != null) {
            approvals.recordAllowed(kind, null, null, reason, preview)
            return ApprovalDecision.Allow(reason)
        }

        val pending = approvals.enqueue(kind, null, null, preview)
        val message = "Access to $historyType history is not approved for MCP. " +
            "A pending approval has been queued (id ${pending.id}). " +
            "Approve it in Burp → MCP → Server → Approvals to set 'Always allow $historyType history', then retry."
        return ApprovalDecision.Deny(message, pending.id)
    }

    // --- Reconciliation ---------------------------------------------------------------------

    /**
     * Drops any queued approval whose target is now allowed by the current rules, recording why.
     *
     * Called whenever anything feeding a rule changes: a security toggle, the approved-targets
     * list, or Burp's own Target → Scope. Without this the queue keeps showing stale rows for
     * hosts the user has already approved somewhere else, which is the main way the Approvals
     * card drifts out of sync with Burp.
     *
     * @return how many pending approvals were cleared.
     */
    fun reconcilePending(): Int {
        // Capture mode writes back into the approved-targets list, which fires the config
        // listener that called us. Without this guard that is an infinite loop.
        if (!reconciling.compareAndSet(false, true)) return 0
        try {
            return doReconcile()
        } finally {
            reconciling.set(false)
        }
    }

    private fun doReconcile(): Int {
        var cleared = 0
        for (pending in approvals.store.list()) {
            val reason = when (pending.kind) {
                ApprovalKind.HTTP_REQUEST -> {
                    val host = pending.host ?: continue
                    // TLS is unknown for a queued entry; isInBurpScope tries both schemes anyway.
                    allowReasonForHttpRequest(host, pending.port, pending.port != 80)
                }
                ApprovalKind.HTTP_HISTORY, ApprovalKind.WEBSOCKET_HISTORY ->
                    allowReasonForHistory(pending.kind)
            } ?: continue

            if (reason == AllowReason.CAPTURE_MODE && pending.host != null) {
                config.addAutoApproveTarget(
                    if (pending.port != null) "${pending.host}:${pending.port}" else pending.host
                )
            }
            if (approvals.resolve(pending.id, reason.toResolution()) != null) cleared++
        }
        return cleared
    }
}
