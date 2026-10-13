package burp.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.HttpService
import burp.api.montoya.http.RedirectionMode
import burp.api.montoya.http.RequestOptions
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.params.HttpParameter
import burp.api.montoya.http.message.params.HttpParameterType
import burp.api.montoya.http.message.requests.HttpRequest
import burp.mcp.McpConfig
import burp.mcp.approval.ApprovalDecision
import burp.mcp.approval.ApprovalPolicy
import burp.mcp.collab.CollaboratorBroker
import burp.mcp.history.McpRequestHistory
import burp.mcp.history.McpRequestRecord
import burp.mcp.history.ProxyHandlerCaptureStore
import burp.mcp.intercept.InterceptManager
import burp.mcp.intercept.MessageResolution
import burp.mcp.intercept.PendingRequest
import burp.mcp.intercept.PendingResponse
import burp.mcp.session.AttachSpec
import burp.mcp.session.CapturedSession
import burp.mcp.session.KeepAliveSpec
import burp.mcp.session.SessionStore
import burp.mcp.session.parseSetCookie
import burp.mcp.session.rollForwardCookies
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.serialization.json.Json
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.JTextArea

private val compactJson = Json { explicitNulls = false }

/** Preview a secret (cookie/token) without printing it whole: first chars + length. */
private fun maskSecret(s: String): String =
    if (s.length <= 12) "${s.take(4)}…(${s.length})" else "${s.take(10)}…(${s.length})"

// parseSetCookie / rollForwardCookies moved to burp.mcp.session.CookieRoll (shared with KeepAliveManager).

// Per-body cap for the proxy-history list/regex views. Applied to each body field before
// serialisation so the emitted JSON is always valid; the single-item and raw tools are uncapped.
private const val PROXY_LIST_BODY_CAP = 5000

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private fun filterProxyHistory(
    items: List<burp.api.montoya.proxy.ProxyHttpRequestResponse>,
    statusCodes: String?,
    methods: String?,
    host: String?,
    mimeTypes: String?,
    inScopeOnly: Boolean
): Sequence<burp.api.montoya.proxy.ProxyHttpRequestResponse> {
    var seq = items.asSequence()

    if (inScopeOnly) {
        seq = seq.filter { try { it.request()?.isInScope == true } catch (_: Exception) { false } }
    }

    if (!methods.isNullOrBlank()) {
        val methodList = methods.split(",").map { it.trim().uppercase() }
        seq = seq.filter { item ->
            try { item.request()?.method()?.uppercase() in methodList } catch (_: Exception) { false }
        }
    }

    if (!host.isNullOrBlank()) {
        seq = seq.filter { item ->
            try {
                val itemHost = item.httpService()?.host() ?: return@filter false
                if (host.startsWith("*.")) {
                    val domain = host.substring(2)
                    itemHost.equals(domain, ignoreCase = true) || itemHost.endsWith(".$domain", ignoreCase = true)
                } else {
                    itemHost.equals(host, ignoreCase = true)
                }
            } catch (_: Exception) { false }
        }
    }

    if (!statusCodes.isNullOrBlank()) {
        val filters = statusCodes.split(",").map { it.trim().lowercase() }
        seq = seq.filter { item ->
            try {
                val code = item.response()?.statusCode()?.toInt() ?: return@filter false
                filters.any { f ->
                    when {
                        f.endsWith("xx") -> {
                            val prefix = f.dropLast(2).toIntOrNull() ?: return@any false
                            code / 100 == prefix
                        }
                        else -> f.toIntOrNull() == code
                    }
                }
            } catch (_: Exception) { false }
        }
    }

    if (!mimeTypes.isNullOrBlank()) {
        val typeList = mimeTypes.split(",").map { it.trim().uppercase() }
        seq = seq.filter { item ->
            try { item.mimeType()?.name?.uppercase() in typeList } catch (_: Exception) { false }
        }
    }

    return seq
}

private fun filterMcpHistory(
    items: List<McpRequestRecord>,
    statusCodes: String?,
    methods: String?,
    host: String?,
    mimeTypes: String?,
    inScopeOnly: Boolean
): Sequence<McpRequestRecord> {
    var seq = items.asSequence()

    if (inScopeOnly) {
        seq = seq.filter { try { it.request.isInScope } catch (_: Exception) { false } }
    }

    if (!methods.isNullOrBlank()) {
        val methodList = methods.split(",").map { it.trim().uppercase() }
        seq = seq.filter { item ->
            try { item.request.method()?.uppercase() in methodList } catch (_: Exception) { false }
        }
    }

    if (!host.isNullOrBlank()) {
        seq = seq.filter { item ->
            try {
                val itemHost = item.request.httpService()?.host() ?: return@filter false
                if (host.startsWith("*.")) {
                    val domain = host.substring(2)
                    itemHost.equals(domain, ignoreCase = true) || itemHost.endsWith(".$domain", ignoreCase = true)
                } else {
                    itemHost.equals(host, ignoreCase = true)
                }
            } catch (_: Exception) { false }
        }
    }

    if (!statusCodes.isNullOrBlank()) {
        val filters = statusCodes.split(",").map { it.trim().lowercase() }
        seq = seq.filter { item ->
            try {
                val code = item.response?.statusCode()?.toInt() ?: return@filter false
                filters.any { f ->
                    when {
                        f.endsWith("xx") -> {
                            val prefix = f.dropLast(2).toIntOrNull() ?: return@any false
                            code / 100 == prefix
                        }
                        else -> f.toIntOrNull() == code
                    }
                }
            } catch (_: Exception) { false }
        }
    }

    if (!mimeTypes.isNullOrBlank()) {
        val typeList = mimeTypes.split(",").map { it.trim().uppercase() }
        seq = seq.filter { item ->
            try { item.response?.mimeType()?.name?.uppercase() in typeList } catch (_: Exception) { false }
        }
    }

    return seq
}

private fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner
    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }
    return if (isInBurpWindow && permanentFocusOwner is JTextArea) permanentFocusOwner else null
}

fun Server.registerTools(
    api: MontoyaApi,
    config: McpConfig,
    interceptManager: InterceptManager,
    policy: ApprovalPolicy,
    requestHistory: McpRequestHistory,
    sessionStore: SessionStore,
    collaborator: CollaboratorBroker,
    handlerCaptures: ProxyHandlerCaptureStore
) {

    // 1. send_http1_request
    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        when (val decision = policy.checkHttpRequest(targetHostname, targetPort, usesHttps, content)) {
            is ApprovalDecision.Allow -> { /* fall through */ }
            is ApprovalDecision.Deny -> {
                api.logging().logToOutput(
                    "MCP HTTP request pending approval: $targetHostname:$targetPort (${decision.pendingId})"
                )
                return@mcpTool decision.reason
            }
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")
        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)
        requestHistory.record(response?.request() ?: request, response?.response(), "HTTP/1.1")
        response?.toString() ?: "<no response>"
    }

    // 2. send_http2_request
    mcpTool<SendHttp2Request>("Issues an HTTP/2 request and returns the response. Do NOT pass headers to the body parameter.") {
        val http2RequestDisplay = buildString {
            pseudoHeaders.forEach { (key, value) ->
                val headerName = if (key.startsWith(":")) key else ":$key"
                appendLine("$headerName: $value")
            }
            headers.forEach { (key, value) -> appendLine("$key: $value") }
            if (requestBody.isNotBlank()) { appendLine(); append(requestBody) }
        }

        when (val decision = policy.checkHttpRequest(targetHostname, targetPort, usesHttps, http2RequestDisplay)) {
            is ApprovalDecision.Allow -> { /* fall through */ }
            is ApprovalDecision.Deny -> {
                api.logging().logToOutput(
                    "MCP HTTP request pending approval: $targetHostname:$targetPort (${decision.pendingId})"
                )
                return@mcpTool decision.reason
            }
        }

        api.logging().logToOutput("MCP HTTP/2 request: $targetHostname:$targetPort")

        val orderedPseudoHeaderNames = listOf(":scheme", ":method", ":path", ":authority")
        val fixedPseudoHeaders = LinkedHashMap<String, String>().apply {
            orderedPseudoHeaderNames.forEach { name ->
                val value = pseudoHeaders[name.removePrefix(":")] ?: pseudoHeaders[name]
                if (value != null) put(name, value)
            }
            pseudoHeaders.forEach { (key, value) ->
                val properKey = if (key.startsWith(":")) key else ":$key"
                if (!containsKey(properKey)) put(properKey, value)
            }
        }

        val headerList = (fixedPseudoHeaders + headers).map { HttpHeader.httpHeader(it.key.lowercase(), it.value) }
        val request = HttpRequest.http2Request(toMontoyaService(), headerList, requestBody)
        val response = api.http().sendRequest(request, HttpMode.HTTP_2)
        requestHistory.record(response?.request() ?: request, response?.response(), "HTTP/2")
        response?.toString() ?: "<no response>"
    }

    // 3. create_repeater_tab
    mcpTool<CreateRepeaterTab>("Creates a new Repeater tab with the specified HTTP request.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.repeater().sendToRepeater(request, tabName)
    }

    // 4. send_to_intruder
    mcpTool<SendToIntruder>("Sends an HTTP request to Intruder.") {
        val request = HttpRequest.httpRequest(toMontoyaService(), content)
        api.intruder().sendToIntruder(request, tabName)
    }

    // 5. url_encode
    mcpTool<UrlEncode>("URL encodes the input string") {
        api.utilities().urlUtils().encode(content)
    }

    // 6. url_decode
    mcpTool<UrlDecode>("URL decodes the input string") {
        api.utilities().urlUtils().decode(content)
    }

    // 7. base64_encode
    mcpTool<Base64Encode>("Base64 encodes the input string") {
        api.utilities().base64Utils().encodeToString(content)
    }

    // 8. base64_decode
    mcpTool<Base64Decode>("Base64 decodes the input string") {
        api.utilities().base64Utils().decode(content).toString()
    }

    // 9. generate_random_string
    mcpTool<GenerateRandomString>("Generates a random string of specified length and character set") {
        api.utilities().randomUtils().randomString(length, characterSet)
    }

    // 10. output_project_options
    mcpTool(
        "output_project_options",
        "Outputs current project-level configuration in JSON format."
    ) {
        api.burpSuite().exportProjectOptionsAsJson()
    }

    // 11. output_user_options
    mcpTool(
        "output_user_options",
        "Outputs current user-level configuration in JSON format."
    ) {
        api.burpSuite().exportUserOptionsAsJson()
    }

    val toolingDisabledMessage =
        "User has disabled configuration editing. They can enable it in the MCP tab in Burp by selecting 'Enable tools that can edit your config'"

    // 12. set_project_options
    mcpTool<SetProjectOptions>("Sets project-level configuration in JSON format. Export first to know the schema.") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting project-level configuration: $json")
            api.burpSuite().importProjectOptionsFromJson(json)
            "Project configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    // 13. set_user_options
    mcpTool<SetUserOptions>("Sets user-level configuration in JSON format. Export first to know the schema.") {
        if (config.configEditingTooling) {
            api.logging().logToOutput("Setting user-level configuration: $json")
            api.burpSuite().importUserOptionsFromJson(json)
            "User configuration has been applied"
        } else {
            toolingDisabledMessage
        }
    }

    // 14. set_task_execution_engine_state
    mcpTool<SetTaskExecutionEngineState>("Sets the state of Burp's task execution engine (paused or unpaused)") {
        api.burpSuite().taskExecutionEngine().state = if (running) RUNNING else PAUSED
        "Task execution engine is now ${if (running) "running" else "paused"}"
    }

    // 15. set_proxy_intercept_state
    mcpTool<SetProxyInterceptState>("Enables or disables Burp Proxy Intercept") {
        if (intercepting) api.proxy().enableIntercept() else api.proxy().disableIntercept()
        "Intercept has been ${if (intercepting) "enabled" else "disabled"}"
    }

    // 16. get_active_editor_contents
    mcpTool("get_active_editor_contents", "Outputs the contents of the user's active message editor") {
        getActiveEditor(api)?.text ?: "<No active editor>"
    }

    // 17. set_active_editor_contents
    mcpTool<SetActiveEditorContents>("Sets the content of the user's active message editor") {
        val editor = getActiveEditor(api) ?: return@mcpTool "<No active editor>"
        if (!editor.isEditable) return@mcpTool "<Current editor is not editable>"
        editor.text = text
        "Editor text has been set"
    }

    val httpHistoryDescription = "Retrieves items from the proxy HTTP history with structured output. " +
        "Set includeRequestBody/includeResponseBody to false to exclude bodies and save tokens (default: true). " +
        "Set includeHeaders to false for a compact metadata-only view (default: true). " +
        "Filter by statusCodes (e.g., '200', '2xx', '4xx,5xx'), methods (e.g., 'GET,POST'), " +
        "host (e.g., 'example.com' or '*.example.com'), mimeTypes (e.g., 'HTML,JSON,SCRIPT,XML'), " +
        "and inScopeOnly (true to limit to in-scope items). " +
        "Each item includes modification flags: requestModified (original client request differs from what was sent to server), " +
        "responseModified (original server response differs from what was returned to client), " +
        "edited (user manually edited in proxy UI). " +
        "Use get_proxy_http_history_item to retrieve full details including all modified versions."

    // 18. get_proxy_http_history (paginated)
    mcpPaginatedTool<GetProxyHttpHistory>(httpHistoryDescription) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        filterProxyHistory(api.proxy().history(), statusCodes, methods, host, mimeTypes, inScopeOnly == true)
            .map { compactJson.encodeToString(it.toSerializableProxyForm(
                includeRequestBody != false, includeResponseBody != false, includeHeaders != false,
                maxBodyChars = PROXY_LIST_BODY_CAP, capture = handlerCaptures.get(it.id())
            )) }
    }

    // 19. get_proxy_http_history_regex (paginated)
    mcpPaginatedTool<GetProxyHttpHistoryRegex>(
        "Searches proxy HTTP history by regex on full request/response content, with the same filtering and output options as get_proxy_http_history."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        val compiledRegex = Pattern.compile(regex)
        filterProxyHistory(api.proxy().history { it.contains(compiledRegex) }, statusCodes, methods, host, mimeTypes, inScopeOnly == true)
            .map { compactJson.encodeToString(it.toSerializableProxyForm(
                includeRequestBody != false, includeResponseBody != false, includeHeaders != false,
                maxBodyChars = PROXY_LIST_BODY_CAP, capture = handlerCaptures.get(it.id())
            )) }
    }

    // 19b. get_proxy_http_history_item (single item by ID)
    mcpTool<GetProxyHttpHistoryItem>(
        "Retrieves a single proxy HTTP history item by its ID with full headers and body. " +
        "When requestModified is true, includes finalRequestHeaders/finalRequestBody (the request actually sent to the server after Burp modifications). " +
        "When responseModified is true, includes originalResponseHeaders/originalResponseBody (the original server response before Burp modifications). " +
        "The base request/response fields always show: request = original from client, response = final delivered to client. " +
        "Use get_proxy_http_history first to browse items and find IDs."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason
        val item = api.proxy().history().firstOrNull { it.id() == id }
            ?: return@mcpTool "No history item found with ID: $id"
        compactJson.encodeToString(item.toSerializableProxyForm(
            includeRequestBody = true, includeResponseBody = true, includeHeaders = true,
            includeModifiedVersions = true, capture = handlerCaptures.get(item.id())
        ))
    }

    val mcpRequestHistoryDescription = "Retrieves the history of HTTP requests issued by this MCP server's own " +
        "send_http1_request and send_http2_request tools. These requests are sent via Burp's HTTP API, which bypasses " +
        "the proxy and Repeater — so they do NOT appear in get_proxy_http_history or the Repeater/Proxy UI. This is the " +
        "only way to retrieve them after the fact (e.g. for findings that were tested directly via the MCP). " +
        "Each item carries requestLength/responseLength (full on-the-wire byte counts) and a timestamp. " +
        "Set includeRequestBody/includeResponseBody to false to exclude bodies, includeHeaders to false for a metadata-only view. " +
        "Filter by statusCodes (e.g. '200', '2xx', '4xx,5xx'), methods (e.g. 'GET,POST'), host (e.g. 'example.com' or '*.example.com'), " +
        "mimeTypes (e.g. 'HTML,JSON'), and inScopeOnly. Newest first. Use get_mcp_request_history_item for a single item by ID."

    // 19c. get_mcp_request_history (paginated)
    mcpPaginatedTool<GetMcpRequestHistory>(mcpRequestHistoryDescription) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        filterMcpHistory(requestHistory.list(), statusCodes, methods, host, mimeTypes, inScopeOnly == true)
            .map { truncateIfNeeded(compactJson.encodeToString(it.toSerializableForm(
                includeRequestBody != false, includeResponseBody != false, includeHeaders != false
            ))) }
    }

    // 19d. get_mcp_request_history_regex (paginated)
    mcpPaginatedTool<GetMcpRequestHistoryRegex>(
        "Searches the MCP-issued request history by regex on full request/response content, with the same filtering and output options as get_mcp_request_history."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        val compiledRegex = Pattern.compile(regex)
        filterMcpHistory(requestHistory.list(), statusCodes, methods, host, mimeTypes, inScopeOnly == true)
            .filter { record ->
                try {
                    compiledRegex.matcher(record.request.toString()).find() ||
                        (record.response?.let { compiledRegex.matcher(it.toString()).find() } ?: false)
                } catch (_: Exception) { false }
            }
            .map { truncateIfNeeded(compactJson.encodeToString(it.toSerializableForm(
                includeRequestBody != false, includeResponseBody != false, includeHeaders != false
            ))) }
    }

    // 19e. get_mcp_request_history_item (single item by ID)
    mcpTool<GetMcpRequestHistoryItem>(
        "Retrieves a single MCP-issued request history item by its ID, with full headers and bodies. " +
        "Use get_mcp_request_history first to browse items and find IDs."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason
        val item = requestHistory.get(id)
            ?: return@mcpTool "No MCP request history item found with ID: $id"
        compactJson.encodeToString(item.toSerializableForm(
            includeRequestBody = true, includeResponseBody = true, includeHeaders = true
        ))
    }

    // 20. get_proxy_websocket_history (paginated)
    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val decision = policy.checkHistory("WebSocket")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // 21. get_proxy_websocket_history_regex (paginated)
    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val decision = policy.checkHistory("WebSocket")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // 22-24. Professional Edition tools
    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        // 22. get_scanner_issues (paginated)
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            val decision = policy.checkHistory("HTTP")
            if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        // 23. generate_collaborator_payload
        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")
            val payload = collaborator.generatePayload(customData)
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${collaborator.serverAddress()}"
        }

        // 24. get_collaborator_interactions
        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload — the interaction id, " +
            "the full payload host, or the payload host with injected prefix labels are all accepted. " +
            "Results are cumulative: every interaction seen for the payload is returned on every call, " +
            "so a later empty result never retracts a hit an earlier call reported."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")
            val interactions = collaborator.poll(payloadId)
            if (interactions.isNotEmpty()) {
                interactions.joinToString("\n\n") { Json.encodeToString(it.toSerializableForm()) }
            } else {
                // Distinguish "polled and nothing came back" from "there was nothing this client
                // could ever have seen" — an agent chasing a blind injection needs to know which.
                val tracked = collaborator.trackedPayloads()
                buildString {
                    append("No interactions detected")
                    if (tracked.isEmpty()) {
                        append(
                            ". Note that this Collaborator client has not generated any payloads, so it " +
                            "cannot see interactions for payloads issued elsewhere (Burp's Collaborator tab, " +
                            "a previous project, or a Collaborator client from before the extension was reloaded). " +
                            "Call generate_collaborator_payload first and use that payload."
                        )
                    } else {
                        append(" for ")
                        append(payloadId?.let { "payload '$it'" } ?: "any of the ${tracked.size} payload(s) this client has issued")
                        append(". Payloads currently tracked: ")
                        append(tracked.takeLast(10).joinToString(", "))
                        if (tracked.size > 10) append(" (+${tracked.size - 10} older)")
                    }
                }
            }
        }
    }

    // === Intercept Tools (25-30) ===

    // 25. set_mcp_intercept_enabled
    mcpTool<SetMcpInterceptEnabled>(
        "Enables or disables MCP-based proxy interception. When enabled, HTTP requests and responses flowing through Burp Proxy " +
        "are held for inspection and can be forwarded (optionally modified) or dropped via MCP tools. " +
        "This is separate from Burp's UI intercept. Disabling auto-forwards all pending messages."
    ) {
        if (enabled) interceptManager.enable() else interceptManager.disable()
        "MCP intercept has been ${if (enabled) "enabled" else "disabled"}"
    }

    // 26. get_intercepted_requests
    mcpTool<GetInterceptedRequests>(
        "Lists pending intercepted HTTP requests with summary info (id, method, URL, timestamp). " +
        "Use get_intercepted_message_detail to see the full raw request content."
    ) {
        val requests = interceptManager.store.pendingRequests()
        if (requests.isEmpty()) return@mcpTool "No pending intercepted requests"
        val paginated = requests.drop(offset).take(count)
        if (paginated.isEmpty()) return@mcpTool "Reached end of items"
        val total = requests.size
        paginated.joinToString("\n\n") { req ->
            "ID: ${req.id}\nMethod: ${req.method}\nURL: ${req.url}\nHost: ${req.host}:${req.port}\nSecure: ${req.secure}\nListener: ${req.listenerInterface}\nTimestamp: ${req.timestamp}\nTotal pending: $total"
        }
    }

    // 27. get_intercepted_responses
    mcpTool<GetInterceptedResponses>(
        "Lists pending intercepted HTTP responses with summary info (id, status code, initiating request URL, timestamp). " +
        "Use get_intercepted_message_detail to see the full raw response content."
    ) {
        val responses = interceptManager.store.pendingResponses()
        if (responses.isEmpty()) return@mcpTool "No pending intercepted responses"
        val paginated = responses.drop(offset).take(count)
        if (paginated.isEmpty()) return@mcpTool "Reached end of items"
        val total = responses.size
        paginated.joinToString("\n\n") { resp ->
            "ID: ${resp.id}\nStatus: ${resp.statusCode}\nRequest: ${resp.initiatingRequestMethod} ${resp.initiatingRequestUrl}\nListener: ${resp.listenerInterface}\nTimestamp: ${resp.timestamp}\nTotal pending: $total"
        }
    }

    // 28. get_intercepted_message_detail
    mcpTool<GetInterceptedMessageDetail>(
        "Gets the full raw content of a specific intercepted message by its ID. " +
        "Use get_intercepted_requests or get_intercepted_responses to find message IDs first."
    ) {
        val message = interceptManager.store.getMessage(messageId)
            ?: return@mcpTool "No pending message found with ID: $messageId"

        when (message) {
            is PendingRequest -> {
                "Type: REQUEST\nID: ${message.id}\nMethod: ${message.method}\nURL: ${message.url}\nHost: ${message.host}:${message.port}\nSecure: ${message.secure}\nListener: ${message.listenerInterface}\nTimestamp: ${message.timestamp}\n\nRaw request:\n${message.rawRequest}"
            }
            is PendingResponse -> {
                "Type: RESPONSE\nID: ${message.id}\nStatus: ${message.statusCode}\nRequest: ${message.initiatingRequestMethod} ${message.initiatingRequestUrl}\nListener: ${message.listenerInterface}\nTimestamp: ${message.timestamp}\n\nRaw response:\n${message.rawResponse}"
            }
        }
    }

    // 29. forward_intercepted_message
    mcpTool<ForwardInterceptedMessage>(
        "Forwards an intercepted message, optionally with modifications. " +
        "Provide either modifiedRaw (a complete replacement raw HTTP message) OR replacements " +
        "(a list of {find, replace} pairs applied in order to the original raw message). Use replacements " +
        "for small targeted edits to large bodies (e.g. tampering a single field in a multi-megabyte JSON " +
        "request) so you do not need to reproduce the whole message. Omit both to forward unchanged."
    ) {
        val message = interceptManager.store.getMessage(messageId)
            ?: return@mcpTool "No pending message found with ID: $messageId"

        if (modifiedRaw != null && modifiedRaw.isBlank()) {
            return@mcpTool "Error: modifiedRaw cannot be blank. Omit it to forward unchanged, or provide valid content."
        }

        if (modifiedRaw != null && replacements != null) {
            return@mcpTool "Error: provide either modifiedRaw or replacements, not both."
        }

        val effectiveRaw: String? = if (replacements != null) {
            if (replacements.isEmpty()) {
                return@mcpTool "Error: replacements list is empty. Omit the parameter to forward unchanged."
            }
            val originalRaw = when (message) {
                is PendingRequest -> message.rawRequest
                is PendingResponse -> message.rawResponse
            }
            var working = originalRaw
            for ((index, r) in replacements.withIndex()) {
                if (r.find.isEmpty()) {
                    return@mcpTool "Error: replacement[$index].find is empty."
                }
                if (!working.contains(r.find)) {
                    val preview = r.find.take(80).replace("\n", "\\n")
                    return@mcpTool "Error: replacement[$index].find not present in the current message: \"$preview\""
                }
                working = working.replace(r.find, r.replace)
            }
            working
        } else {
            modifiedRaw
        }

        interceptManager.store.removeMessage(messageId)
        message.future.complete(MessageResolution.Forward(effectiveRaw))
        val mode = when {
            replacements != null -> " (${replacements.size} replacement(s))"
            modifiedRaw != null -> " (modified)"
            else -> ""
        }
        api.logging().logToOutput("MCP forwarded message $messageId$mode")
        "Message $messageId has been forwarded${if (effectiveRaw != null) " with modifications" else ""}"
    }

    // 30. drop_intercepted_message
    mcpTool<DropInterceptedMessage>(
        "Drops an intercepted message, preventing it from being sent. " +
        "For requests, the server will not receive the request. " +
        "For responses, the client will not receive the response."
    ) {
        val message = interceptManager.store.removeMessage(messageId)
            ?: return@mcpTool "No pending message found with ID: $messageId"

        message.future.complete(MessageResolution.Drop)
        api.logging().logToOutput("MCP dropped message $messageId")
        "Message $messageId has been dropped"
    }

    // 31. replay_proxy_history_item — capture -> mutate one thing -> resend byte-faithfully
    mcpTool<ReplayProxyHistoryItem>(
        "Replays a captured proxy history request with surgical mutations, preserving every other byte " +
        "(header order, casing, cookies) so the request stays browser-faithful. Find the id via " +
        "get_proxy_http_history. Apply any of: replacements (ordered find/replace on the raw message), " +
        "setHeaders (add-or-update), updateParams (type url|body|cookie), setBody, setPath, setMethod, and " +
        "retargetHost/retargetPort/retargetTls. Control transport with httpMode (AUTO|HTTP_1|HTTP_2|HTTP_2_IGNORE_ALPN), " +
        "sni, redirectionMode (ALWAYS|NEVER|SAME_HOST|IN_SCOPE), responseTimeoutMs. Returns the exact request sent and the response."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason

        val item = api.proxy().history().firstOrNull { it.id() == id }
            ?: return@mcpTool "No history item found with ID: $id"
        var request = (try { item.finalRequest() } catch (_: Exception) { null } ?: item.request())
            ?: return@mcpTool "History item $id has no request"

        // Retarget first so raw rebuilds and downstream mutations keep the new service.
        if (retargetHost != null || retargetPort != null || retargetTls != null) {
            val svc = request.httpService()
            request = request.withService(
                HttpService.httpService(retargetHost ?: svc.host(), retargetPort ?: svc.port(), retargetTls ?: svc.secure())
            )
        }

        // Ordered raw find/replace (same semantics as forward_intercepted_message), then rebuild.
        if (!replacements.isNullOrEmpty()) {
            var working = request.toString()
            for ((index, r) in replacements.withIndex()) {
                if (r.find.isEmpty()) return@mcpTool "Error: replacement[$index].find is empty."
                if (!working.contains(r.find)) {
                    val preview = r.find.take(80).replace("\n", "\\n")
                    return@mcpTool "Error: replacement[$index].find not present: \"$preview\""
                }
                working = working.replace(r.find, r.replace)
            }
            request = HttpRequest.httpRequest(request.httpService(), working)
        }

        if (setMethod != null) request = request.withMethod(setMethod)
        if (setPath != null) request = request.withPath(setPath)
        if (setBody != null) request = request.withBody(setBody)
        setHeaders?.forEach { (k, v) -> request = request.withUpdatedHeader(k, v) }
        updateParams?.forEach { p ->
            val type = when (p.type.lowercase()) {
                "url" -> HttpParameterType.URL
                "body" -> HttpParameterType.BODY
                "cookie" -> HttpParameterType.COOKIE
                else -> return@mcpTool "Error: unknown param type '${p.type}' (use url|body|cookie)"
            }
            request = request.withParameter(HttpParameter.parameter(p.name, p.value, type))
        }

        var opts = RequestOptions.requestOptions()
        if (httpMode != null) {
            val mode = try { HttpMode.valueOf(httpMode.uppercase()) } catch (_: Exception) {
                return@mcpTool "Error: invalid httpMode '$httpMode' (AUTO|HTTP_1|HTTP_2|HTTP_2_IGNORE_ALPN)"
            }
            opts = opts.withHttpMode(mode)
        }
        if (sni != null) opts = opts.withServerNameIndicator(sni)
        if (redirectionMode != null) {
            val rm = try { RedirectionMode.valueOf(redirectionMode.uppercase()) } catch (_: Exception) {
                return@mcpTool "Error: invalid redirectionMode '$redirectionMode' (ALWAYS|NEVER|SAME_HOST|IN_SCOPE)"
            }
            opts = opts.withRedirectionMode(rm)
        }
        if (responseTimeoutMs != null) opts = opts.withResponseTimeout(responseTimeoutMs)

        // Gate on the service this will ACTUALLY reach: retargetHost/Port/Tls can point a
        // history item at a host the user never approved.
        val sendService = request.httpService()
        val sendDecision = policy.checkHttpRequest(
            sendService.host(), sendService.port(), sendService.secure(), request.toString()
        )
        if (sendDecision is ApprovalDecision.Deny) return@mcpTool sendDecision.reason

        api.logging().logToOutput("MCP replay of history item $id -> ${sendService.host()}")
        val response = api.http().sendRequest(request, opts)
        requestHistory.record(response?.request() ?: request, response?.response(), "replay")
        buildString {
            appendLine("=== SENT REQUEST ===")
            appendLine(request.toString())
            appendLine()
            appendLine("=== RESPONSE ===")
            append(response?.response()?.toString() ?: "<no response>")
        }
    }

    // ── Session broker: capture per-role sessions, replay captured requests AS a role ──────────

    mcpTool<SessionCapture>(
        "Capture a principal's live session from proxy history and store it under <role> for later " +
        "replay-as-role — the core primitive for concurrent multi-principal / IDOR testing without " +
        "re-login or a device. Provide EITHER `id` (a specific proxy history item to snapshot) OR " +
        "`host` (snapshots the MOST RECENT request seen to that host). Captures the request's Cookie + " +
        "Authorization headers, plus any `headerNames` you list (e.g. a bearer/session-token header the " +
        "app carries outside Authorization). Persisted in the Burp project file (banked roles survive " +
        "restarts) and shown in the MCP 'Sessions' tab. Drive each principal's login once, capture it, " +
        "then use session_replay_as."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason
        val item = when {
            id != null -> api.proxy().history().firstOrNull { it.id() == id }
                ?: return@mcpTool "No history item found with ID: $id"
            host != null -> api.proxy().history().lastOrNull { hi ->
                val req = (try { hi.finalRequest() } catch (_: Exception) { null } ?: hi.request())
                req?.httpService()?.host()?.contains(host, ignoreCase = true) == true
            } ?: return@mcpTool "No proxy history request found for a host containing: $host"
            else -> return@mcpTool "Error: provide either `id` (history item) or `host` to capture from."
        }
        val req = (try { item.finalRequest() } catch (_: Exception) { null } ?: item.request())
            ?: return@mcpTool "History item ${item.id()} has no request to capture."

        val extra = LinkedHashMap<String, String>()
        headerNames?.forEach { name ->
            val v = req.headerValue(name)
            if (v != null) extra[name] = v
        }
        val session = CapturedSession(
            role = role,
            host = req.httpService().host(),
            cookie = req.headerValue("Cookie"),
            authorization = req.headerValue("Authorization"),
            extraHeaders = extra,
            capturedAt = System.currentTimeMillis(),
            sourceId = item.id(),
            note = note
        )
        sessionStore.put(session)
        api.logging().logToOutput("MCP session captured for role '$role' from ${session.host} (item ${item.id()})")
        buildString {
            appendLine("Captured session for role '$role' from ${session.host} (proxy history item ${item.id()}).")
            appendLine("  Cookie: ${session.cookie?.let { maskSecret(it) } ?: "<none>"}")
            appendLine("  Authorization: ${if (session.authorization != null) "present" else "<none>"}")
            if (extra.isNotEmpty()) appendLine("  extra headers: ${extra.keys.joinToString(", ")}")
            if (session.cookie == null && session.authorization == null && extra.isEmpty())
                appendLine("  WARNING: no Cookie/Authorization/named headers found on that request — nothing to replay.")
            append("Now use session_replay_as with role='$role' to send captured requests AS this principal.")
        }
    }

    mcpTool("session_list", "List the roles that currently have a captured session (role, host, age, cookie preview).") {
        val list = sessionStore.list()
        if (list.isEmpty()) {
            "No sessions captured yet. Drive a principal's login, then session_capture(role, id|host)."
        } else {
            list.joinToString("\n") { s ->
                val age = (System.currentTimeMillis() - s.capturedAt) / 1000
                "${s.role}  host=${s.host}  age=${age}s  cookie=${s.cookie?.let { maskSecret(it) } ?: "-"}  " +
                    "auth=${if (s.authorization != null) "y" else "n"}  extra=[${s.extraHeaders.keys.joinToString(",")}]"
            }
        }
    }

    mcpTool<SessionGet>(
        "Return the stored session material for <role> (Cookie + Authorization + extra headers) so you can " +
        "attach it to your own requests. Prefer session_replay_as to replay a captured request AS a role."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason
        val s = sessionStore.get(role)
            ?: return@mcpTool "No session stored for role '$role'. Capture it first with session_capture(role, id|host)."
        buildString {
            appendLine("role: ${s.role}")
            appendLine("host: ${s.host}")
            if (s.cookie != null) appendLine("Cookie: ${s.cookie}")
            if (s.authorization != null) appendLine("Authorization: ${s.authorization}")
            s.extraHeaders.forEach { (k, v) -> appendLine("$k: $v") }
        }
    }

    mcpTool<SessionReplayAs>(
        "Replay a captured proxy history request (by `id`) AS a different principal: swaps in <role>'s stored " +
        "Cookie/Authorization/session headers (from session_capture), then applies optional mutations " +
        "(setHeaders, updateParams type url|body|cookie, setBody, setPath, setMethod, retargetHost/Port/Tls), " +
        "and sends it. This is the IDOR/authz primitive — e.g. replay owner_a's object-fetch AS tenant_b and " +
        "check whether the backend leaks a's data to b. Returns the exact request sent and the response. On a " +
        "target that rotates its session token per response, <role>'s stored cookie is rolled forward from the " +
        "response Set-Cookie, so multi-step replay chains keep working instead of 401ing after the first request."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason

        // Serialize the whole read -> send -> roll-forward per role: two concurrent replays of the same
        // role would both read the same stored cookie, letting the store fall >=2 rotations behind the
        // server — which on a rotate-and-wipe-on-stale target WIPES the session for every consumer.
        return@mcpTool sessionStore.withGate(role) {
        val session = sessionStore.get(role)
            ?: return@mcpTool "No session stored for role '$role'. Capture it first with session_capture(role, id|host)."

        val item = api.proxy().history().firstOrNull { it.id() == id }
            ?: return@mcpTool "No history item found with ID: $id"
        var request = (try { item.finalRequest() } catch (_: Exception) { null } ?: item.request())
            ?: return@mcpTool "History item $id has no request"

        // Retarget first so raw rebuilds and downstream mutations keep the new service.
        if (retargetHost != null || retargetPort != null || retargetTls != null) {
            val svc = request.httpService()
            request = request.withService(
                HttpService.httpService(retargetHost ?: svc.host(), retargetPort ?: svc.port(), retargetTls ?: svc.secure())
            )
        }

        // Inject the role's session — the whole point of the tool.
        if (session.cookie != null) request = request.withUpdatedHeader("Cookie", session.cookie)
        if (session.authorization != null) request = request.withUpdatedHeader("Authorization", session.authorization)
        session.extraHeaders.forEach { (k, v) -> request = request.withUpdatedHeader(k, v) }

        // Optional user mutations (after the swap so they can override a session header if needed).
        if (setMethod != null) request = request.withMethod(setMethod)
        if (setPath != null) request = request.withPath(setPath)
        if (setBody != null) request = request.withBody(setBody)
        setHeaders?.forEach { (k, v) -> request = request.withUpdatedHeader(k, v) }
        updateParams?.forEach { p ->
            val type = when (p.type.lowercase()) {
                "url" -> HttpParameterType.URL
                "body" -> HttpParameterType.BODY
                "cookie" -> HttpParameterType.COOKIE
                else -> return@mcpTool "Error: unknown param type '${p.type}' (use url|body|cookie)"
            }
            request = request.withParameter(HttpParameter.parameter(p.name, p.value, type))
        }

        var opts = RequestOptions.requestOptions()
        if (httpMode != null) {
            val mode = try { HttpMode.valueOf(httpMode.uppercase()) } catch (_: Exception) {
                return@mcpTool "Error: invalid httpMode '$httpMode' (AUTO|HTTP_1|HTTP_2|HTTP_2_IGNORE_ALPN)"
            }
            opts = opts.withHttpMode(mode)
        }
        if (redirectionMode != null) {
            val rm = try { RedirectionMode.valueOf(redirectionMode.uppercase()) } catch (_: Exception) {
                return@mcpTool "Error: invalid redirectionMode '$redirectionMode' (ALWAYS|NEVER|SAME_HOST|IN_SCOPE)"
            }
            opts = opts.withRedirectionMode(rm)
        }
        if (responseTimeoutMs != null) opts = opts.withResponseTimeout(responseTimeoutMs)

        // Gate on the service this will ACTUALLY reach: retargetHost/Port/Tls can point a
        // history item at a host the user never approved.
        val sendService = request.httpService()
        val sendDecision = policy.checkHttpRequest(
            sendService.host(), sendService.port(), sendService.secure(), request.toString()
        )
        if (sendDecision is ApprovalDecision.Deny) return@mcpTool sendDecision.reason

        api.logging().logToOutput("MCP replay of history item $id AS role '$role' -> ${sendService.host()}")
        val response = api.http().sendRequest(request, opts)
        requestHistory.record(response?.request() ?: request, response?.response(), "replay-as:$role")

        // Roll the role's session forward on any Set-Cookie in the response. A target that rotates its
        // session token every response would otherwise 401 on the NEXT
        // replay, because the stored Cookie is a stale snapshot. Merge by name into the role's stored
        // Cookie (per-role → concurrent principals don't collide), persist it, and ALSO mirror into
        // Burp's cookie jar so Burp's own session-handling / UI reflect the rotation.
        var rolledNote = ""
        response?.response()?.let { resp ->
            val setCookies = resp.headers()
                .filter { it.name().equals("Set-Cookie", ignoreCase = true) }
                .map { it.value() }
            if (setCookies.isNotEmpty()) {
                val rolled = rollForwardCookies(session.cookie, setCookies)
                if (rolled.isNotEmpty() && rolled != session.cookie) {
                    sessionStore.put(session.copy(cookie = rolled))
                    rolledNote = " (session cookie rolled forward from Set-Cookie for next replay)"
                }
                val host = request.httpService().host()
                for (sc in setCookies) {
                    parseSetCookie(sc)?.let { (name, value) ->
                        runCatching { api.http().cookieJar().setCookie(name, value, "/", host, null) }
                    }
                }
            }
        }

        sessionStore.touchActivity(role)
        buildString {
            appendLine("=== REPLAYED history item $id AS role '$role'$rolledNote ===")
            appendLine("=== SENT REQUEST ===")
            appendLine(request.toString())
            appendLine()
            appendLine("=== RESPONSE ===")
            append(response?.response()?.toString() ?: "<no response>")
        }
        }
    }

    // 31b. session_keepalive — per-role scripted keepalive, run under the role's replay lock
    mcpTool<SessionKeepAlive>(
        "Register (or update / disable) a per-role KEEPALIVE for a captured session: a script the burp-mcp " +
        "runs on a timer, under the role's replay lock, to keep a session that expires when idle (or whose " +
        "token rotates each response) valid without acting as a concurrent second caller. The `script` " +
        "(language default 'groovy'; any JSR-223 engine on Burp's classpath) receives `ctx`: ctx.session " +
        "(host/cookie/authorization), ctx.send(method, path[, headers][, body]) -> {status, location, " +
        "setCookies, headers, body} sent as the role (redirects not followed), ctx.rollForward(setCookies), " +
        "ctx.setCookie(header), ctx.markDead(reason), ctx.log(msg). Runs every `intervalSec` (default 180) " +
        "only when the role has not been replayed within that window, so it never overlaps live traffic. " +
        "enabled=false or an omitted script disables it."
    ) {
        if (!enabled || script == null) {
            val removed = sessionStore.removeKeepAlive(role)
            return@mcpTool if (removed != null) "Keepalive disabled + removed for role '$role'."
            else "No keepalive was registered for role '$role'."
        }
        // The keepalive fires on a timer with no tool call behind it, so this is the only
        // chance to check the target. Port/TLS are not stored with a session, so gate on host.
        val keepAliveHost = sessionStore.get(role)?.host
            ?: return@mcpTool "No session stored for role '$role'. Capture it first with session_capture(role, id|host)."
        val gateDecision = policy.checkHttpRequest(
            keepAliveHost, null, true,
            "A keepalive script for role '$role' will send requests to $keepAliveHost every ${intervalSec}s."
        )
        if (gateDecision is ApprovalDecision.Deny) return@mcpTool gateDecision.reason

        sessionStore.putKeepAlive(
            KeepAliveSpec(role = role, language = language, script = script, intervalMs = intervalSec.toLong() * 1000L, enabled = true)
        )
        "Keepalive registered for role '$role' (language=$language, every ${intervalSec}s), run under the " +
            "role's serial replay lock. It fires only when '$role' has not been replayed within ${intervalSec}s."
    }

    // 31c. session_attach — inject a role's session into a marked browser routed through Burp
    mcpTool<SessionAttach>(
        "Attach a captured role's session to a live browser routed through Burp: requests to the role's " +
        "host carrying the opaque marker header (name default 'X-Cid'; value is a generated neutral token, " +
        "no role or project name) get the role's CURRENT stored Cookie/Authorization injected and the " +
        "response rolled forward — so a browser and the `session_replay_as` API share ONE coherent session " +
        "instead of diverging. Returns the header name + token to set as Playwright `extraHTTPHeaders`; the " +
        "token also tags that browser's traffic in Burp (annotation note) so concurrent browsers are " +
        "distinguishable, and the marker header is stripped before the request reaches the target. " +
        "`serialize` (default true) gates the role's requests one at a time through the per-role semaphore. " +
        "`enabled=false` detaches (by token if given, else all attaches for the role)."
    ) {
        if (!enabled) {
            if (token != null) {
                val r = sessionStore.removeAttach(token)
                return@mcpTool if (r != null) "Detached token (role '${r.role}')." else "No attach found for that token."
            }
            val removed = sessionStore.attaches().filter { it.role == role }.count { sessionStore.removeAttach(it.token) != null }
            return@mcpTool "Detached $removed attach(es) for role '$role'."
        }
        val s = sessionStore.get(role)
            ?: return@mcpTool "No session stored for role '$role'. Capture it first with session_capture(role, id|host)."
        // Attaching arms credential injection for future browser traffic to this host, so gate it
        // the same way as the tools that send directly. Port/TLS are not stored with a session.
        val attachDecision = policy.checkHttpRequest(
            host ?: s.host, null, true,
            "Attach role '$role''s session to browser traffic reaching ${host ?: s.host}."
        )
        if (attachDecision is ApprovalDecision.Deny) return@mcpTool attachDecision.reason
        val tok = token ?: java.util.UUID.randomUUID().toString().replace("-", "").substring(0, 16)
        val h = host ?: s.host
        sessionStore.putAttach(AttachSpec(token = tok, role = role, host = h, headerName = headerName, serialize = serialize))
        buildString {
            appendLine("Attached role '$role' to browsers carrying:  $headerName: $tok")
            appendLine("Set that as a Playwright extraHTTPHeaders entry on the browser (routed through this Burp).")
            appendLine("Requests to $h with it get '$role''s session injected + rolled forward" +
                (if (serialize) ", serialized one-at-a-time per role." else " (not serialized)."))
            append("The token also tags this browser's traffic in Burp. Detach: session_attach role=$role enabled=false.")
        }
    }

    // 32. get_proxy_http_history_item_raw — untruncated raw bytes for faithful round-tripping
    mcpTool<GetProxyHttpHistoryItemRaw>(
        "Retrieves the FULL raw bytes of a proxy history item (rawRequest + rawFinalRequest + response), " +
        "untruncated and including the request start-line the split headers/body fields drop. Use this to " +
        "get an exact request to hand to send_http1_request, or use replay_proxy_history_item to mutate + resend."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason
        val item = api.proxy().history().firstOrNull { it.id() == id }
            ?: return@mcpTool "No history item found with ID: $id"
        compactJson.encodeToString(
            item.toSerializableProxyForm(
                includeRequestBody = true, includeResponseBody = true, includeHeaders = true,
                includeModifiedVersions = true, includeRaw = true, capture = handlerCaptures.get(item.id())
            )
        )
    }

    // 33. intruder_batch — programmatic Intruder analog (send_to_intruder only opens the UI)
    mcpTool<IntruderBatch>(
        "Runs an Intruder-style batch: takes a base request (baseId from proxy history, or baseContent + " +
        "targetHostname/targetPort/usesHttps), substitutes the literal marker with each payload, sends them " +
        "(optionally throttled with throttleMs), and returns per-payload status/length/timing. Unlike " +
        "send_to_intruder (UI only), this executes and returns results. Set httpMode to pin the HTTP version."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpTool decision.reason
        if (marker.isEmpty()) return@mcpTool "Error: marker must be non-empty."
        if (payloads.isEmpty()) return@mcpTool "Error: payloads list is empty."

        val base: HttpRequest = when {
            baseId != null -> {
                val item = api.proxy().history().firstOrNull { it.id() == baseId }
                    ?: return@mcpTool "No history item found with ID: $baseId"
                (try { item.finalRequest() } catch (_: Exception) { null } ?: item.request())
                    ?: return@mcpTool "History item $baseId has no request"
            }
            baseContent != null && targetHostname != null && targetPort != null && usesHttps != null ->
                HttpRequest.httpRequest(
                    HttpService.httpService(targetHostname, targetPort, usesHttps),
                    baseContent.replace("\r", "").replace("\n", "\r\n")
                )
            else -> return@mcpTool "Error: provide baseId, or baseContent + targetHostname + targetPort + usesHttps."
        }

        val baseRaw = base.toString()
        if (!baseRaw.contains(marker)) return@mcpTool "Error: marker '$marker' not present in the base request."
        val service = base.httpService()
        // One gate for the whole batch: every payload goes to this same service.
        val sendDecision = policy.checkHttpRequest(
            service.host(), service.port(), service.secure(), baseRaw
        )
        if (sendDecision is ApprovalDecision.Deny) return@mcpTool sendDecision.reason

        val mode = httpMode?.let { try { HttpMode.valueOf(it.uppercase()) } catch (_: Exception) { null } }

        api.logging().logToOutput("MCP intruder_batch: ${payloads.size} payloads -> ${service.host()}")
        val results = ArrayList<IntruderResult>(payloads.size)
        for (payload in payloads) {
            val req = HttpRequest.httpRequest(service, baseRaw.replace(marker, payload))
            val start = System.currentTimeMillis()
            try {
                val resp = if (mode != null) api.http().sendRequest(req, mode) else api.http().sendRequest(req)
                results.add(
                    IntruderResult(
                        payload = payload,
                        statusCode = try { resp?.response()?.statusCode()?.toInt() } catch (_: Exception) { null },
                        responseLength = try { resp?.response()?.toByteArray()?.length() } catch (_: Exception) { null },
                        timingMs = System.currentTimeMillis() - start
                    )
                )
            } catch (e: Exception) {
                results.add(IntruderResult(payload = payload, error = e.message))
            }
            if (throttleMs != null && throttleMs > 0) Thread.sleep(throttleMs.toLong())
        }
        compactJson.encodeToString(results)
    }

    // 34. get_site_map — enumerate endpoints Burp already discovered (browse first, then read this)
    mcpPaginatedTool<GetSiteMap>(
        "Lists endpoints in Burp's site map (populated by browsing/proxying the app), optionally filtered by " +
        "url prefix. Use this instead of re-crawling with curl — it reflects what the real browser already reached."
    ) {
        val decision = policy.checkHistory("HTTP")
        if (decision is ApprovalDecision.Deny) return@mcpPaginatedTool sequenceOf(decision.reason)
        api.siteMap().requestResponses().asSequence()
            .filter { rr ->
                prefix == null || (try { rr.request()?.url()?.startsWith(prefix) == true } catch (_: Exception) { false })
            }
            .map { rr ->
                val req = try { rr.request() } catch (_: Exception) { null }
                val resp = try { rr.response() } catch (_: Exception) { null }
                compactJson.encodeToString(
                    SiteMapEntry(
                        url = try { req?.url() } catch (_: Exception) { null },
                        method = try { req?.method() } catch (_: Exception) { null },
                        statusCode = try { resp?.statusCode()?.toInt() } catch (_: Exception) { null },
                        mimeType = try { resp?.mimeType()?.name } catch (_: Exception) { null }
                    )
                )
            }
    }
}
