package burp.mcp.tools

import burp.api.montoya.MontoyaApi
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.PAUSED
import burp.api.montoya.burpsuite.TaskExecutionEngine.TaskExecutionEngineState.RUNNING
import burp.api.montoya.collaborator.InteractionFilter
import burp.api.montoya.core.BurpSuiteEdition
import burp.api.montoya.http.HttpMode
import burp.api.montoya.http.message.HttpHeader
import burp.api.montoya.http.message.requests.HttpRequest
import burp.mcp.McpConfig
import burp.mcp.intercept.InterceptManager
import burp.mcp.intercept.MessageResolution
import burp.mcp.intercept.PendingRequest
import burp.mcp.intercept.PendingResponse
import io.modelcontextprotocol.kotlin.sdk.server.Server
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.awt.KeyboardFocusManager
import java.util.regex.Pattern
import javax.swing.*
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

private fun truncateIfNeeded(serialized: String): String {
    return if (serialized.length > 5000) {
        serialized.substring(0, 5000) + "... (truncated)"
    } else {
        serialized
    }
}

private suspend fun checkHttpRequestPermission(
    hostname: String, port: Int, config: McpConfig, content: String, api: MontoyaApi
): Boolean {
    if (!config.requireHttpRequestApproval) return true

    val autoApproved = config.getAutoApproveTargetsList().any { approved ->
        when {
            approved.equals("$hostname:$port", ignoreCase = true) -> true
            approved.equals(hostname, ignoreCase = true) -> true
            approved.startsWith("*.") -> {
                val domain = approved.substring(2)
                hostname.endsWith(".$domain", ignoreCase = true)
            }
            else -> false
        }
    }
    if (autoApproved) return true

    return suspendCoroutine { continuation ->
        SwingUtilities.invokeLater {
            val message = "An MCP client is requesting to send an HTTP request to:\n\nTarget: $hostname:$port\n"
            val options = arrayOf("Allow Once", "Always Allow Host", "Always Allow Host:Port", "Deny")
            val result = JOptionPane.showOptionDialog(
                null, message, "MCP HTTP Request Approval",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]
            )
            when (result) {
                0 -> continuation.resume(true)
                1 -> { config.addAutoApproveTarget(hostname); continuation.resume(true) }
                2 -> { config.addAutoApproveTarget("$hostname:$port"); continuation.resume(true) }
                else -> continuation.resume(false)
            }
        }
    }
}

private suspend fun checkHistoryPermission(
    historyType: String, config: McpConfig, api: MontoyaApi
): Boolean {
    if (!config.requireHistoryAccessApproval) return true

    val alwaysAllowed = when (historyType) {
        "HTTP" -> config.alwaysAllowHttpHistory
        "WebSocket" -> config.alwaysAllowWebSocketHistory
        else -> false
    }
    if (alwaysAllowed) return true

    return suspendCoroutine { continuation ->
        SwingUtilities.invokeLater {
            val message = "An MCP client is requesting access to your Burp Suite $historyType history.\n\n" +
                "This may include sensitive data from previous web sessions.\n"
            val options = arrayOf("Allow Once", "Always Allow $historyType History", "Deny")
            val result = JOptionPane.showOptionDialog(
                null, message, "MCP History Access",
                JOptionPane.DEFAULT_OPTION, JOptionPane.QUESTION_MESSAGE, null, options, options[0]
            )
            when (result) {
                0 -> continuation.resume(true)
                1 -> {
                    when (historyType) {
                        "HTTP" -> config.alwaysAllowHttpHistory = true
                        "WebSocket" -> config.alwaysAllowWebSocketHistory = true
                    }
                    continuation.resume(true)
                }
                else -> continuation.resume(false)
            }
        }
    }
}

private fun getActiveEditor(api: MontoyaApi): JTextArea? {
    val frame = api.userInterface().swingUtils().suiteFrame()
    val focusManager = KeyboardFocusManager.getCurrentKeyboardFocusManager()
    val permanentFocusOwner = focusManager.permanentFocusOwner
    val isInBurpWindow = generateSequence(permanentFocusOwner) { it.parent }.any { it == frame }
    return if (isInBurpWindow && permanentFocusOwner is JTextArea) permanentFocusOwner else null
}

fun Server.registerTools(api: MontoyaApi, config: McpConfig, interceptManager: InterceptManager) {

    // 1. send_http1_request
    mcpTool<SendHttp1Request>("Issues an HTTP/1.1 request and returns the response.") {
        val allowed = runBlocking {
            checkHttpRequestPermission(targetHostname, targetPort, config, content, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
        }

        api.logging().logToOutput("MCP HTTP/1.1 request: $targetHostname:$targetPort")
        val fixedContent = content.replace("\r", "").replace("\n", "\r\n")
        val request = HttpRequest.httpRequest(toMontoyaService(), fixedContent)
        val response = api.http().sendRequest(request)
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

        val allowed = runBlocking {
            checkHttpRequestPermission(targetHostname, targetPort, config, http2RequestDisplay, api)
        }
        if (!allowed) {
            api.logging().logToOutput("MCP HTTP request denied: $targetHostname:$targetPort")
            return@mcpTool "Send HTTP request denied by Burp Suite"
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

    // 18. get_proxy_http_history (paginated)
    mcpPaginatedTool<GetProxyHttpHistory>("Displays items within the proxy HTTP history") {
        val allowed = runBlocking { checkHistoryPermission("HTTP", config, api) }
        if (!allowed) return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        api.proxy().history().asSequence().map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // 19. get_proxy_http_history_regex (paginated)
    mcpPaginatedTool<GetProxyHttpHistoryRegex>("Displays items matching a specified regex within the proxy HTTP history") {
        val allowed = runBlocking { checkHistoryPermission("HTTP", config, api) }
        if (!allowed) return@mcpPaginatedTool sequenceOf("HTTP history access denied by Burp Suite")
        val compiledRegex = Pattern.compile(regex)
        api.proxy().history { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // 20. get_proxy_websocket_history (paginated)
    mcpPaginatedTool<GetProxyWebsocketHistory>("Displays items within the proxy WebSocket history") {
        val allowed = runBlocking { checkHistoryPermission("WebSocket", config, api) }
        if (!allowed) return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        api.proxy().webSocketHistory().asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // 21. get_proxy_websocket_history_regex (paginated)
    mcpPaginatedTool<GetProxyWebsocketHistoryRegex>("Displays items matching a specified regex within the proxy WebSocket history") {
        val allowed = runBlocking { checkHistoryPermission("WebSocket", config, api) }
        if (!allowed) return@mcpPaginatedTool sequenceOf("WebSocket history access denied by Burp Suite")
        val compiledRegex = Pattern.compile(regex)
        api.proxy().webSocketHistory { it.contains(compiledRegex) }.asSequence()
            .map { truncateIfNeeded(Json.encodeToString(it.toSerializableForm())) }
    }

    // 22-24. Professional Edition tools
    if (api.burpSuite().version().edition() == BurpSuiteEdition.PROFESSIONAL) {
        // 22. get_scanner_issues (paginated)
        mcpPaginatedTool<GetScannerIssues>("Displays information about issues identified by the scanner") {
            api.siteMap().issues().asSequence().map { Json.encodeToString(it.toSerializableForm()) }
        }

        val collaboratorClient by lazy { api.collaborator().createClient() }

        // 23. generate_collaborator_payload
        mcpTool<GenerateCollaboratorPayload>(
            "Generates a Burp Collaborator payload URL for out-of-band (OOB) testing. " +
            "Use get_collaborator_interactions with the returned payloadId to check for interactions."
        ) {
            api.logging().logToOutput("MCP generating Collaborator payload${customData?.let { " with custom data" } ?: ""}")
            val payload = if (customData != null) {
                collaboratorClient.generatePayload(customData)
            } else {
                collaboratorClient.generatePayload()
            }
            val server = collaboratorClient.server()
            "Payload: $payload\nPayload ID: ${payload.id()}\nCollaborator server: ${server.address()}"
        }

        // 24. get_collaborator_interactions
        mcpTool<GetCollaboratorInteractions>(
            "Polls Burp Collaborator for out-of-band interactions (DNS, HTTP, SMTP). " +
            "Optionally filter by payloadId from generate_collaborator_payload."
        ) {
            api.logging().logToOutput("MCP polling Collaborator interactions${payloadId?.let { " for payload: $it" } ?: ""}")
            val interactions = if (payloadId != null) {
                collaboratorClient.getInteractions(InteractionFilter.interactionIdFilter(payloadId))
            } else {
                collaboratorClient.getAllInteractions()
            }
            if (interactions.isEmpty()) {
                "No interactions detected"
            } else {
                interactions.joinToString("\n\n") { Json.encodeToString(it.toSerializableForm()) }
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
        "Forwards an intercepted message, optionally with modified raw content. " +
        "If modifiedRaw is provided, the modified content replaces the original request or response. " +
        "If not provided, the original message is forwarded unchanged."
    ) {
        val message = interceptManager.store.getMessage(messageId)
            ?: return@mcpTool "No pending message found with ID: $messageId"

        if (modifiedRaw != null && modifiedRaw.isBlank()) {
            return@mcpTool "Error: modifiedRaw cannot be blank. Omit it to forward unchanged, or provide valid content."
        }

        interceptManager.store.removeMessage(messageId)
        message.future.complete(MessageResolution.Forward(modifiedRaw))
        api.logging().logToOutput("MCP forwarded message $messageId${if (modifiedRaw != null) " (modified)" else ""}")
        "Message $messageId has been forwarded${if (modifiedRaw != null) " with modifications" else ""}"
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
}
