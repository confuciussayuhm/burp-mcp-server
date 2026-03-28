package burp.mcp.tools

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import kotlinx.serialization.Serializable

fun AuditIssue.toSerializableForm(): IssueDetails {
    return IssueDetails(
        name = name(),
        detail = detail(),
        remediation = remediation(),
        httpService = SerializableHttpService(
            host = httpService().host(),
            port = httpService().port(),
            secure = httpService().secure()
        ),
        baseUrl = baseUrl(),
        severity = AuditIssueSeverity.valueOf(severity().name),
        confidence = AuditIssueConfidence.valueOf(confidence().name),
        requestResponses = requestResponses().map { it.toSerializableForm() },
        collaboratorInteractions = collaboratorInteractions().map {
            SerializableInteraction(
                interactionId = it.id().toString(),
                timestamp = it.timeStamp().toString()
            )
        },
        definition = SerializableAuditIssueDefinition(
            id = definition().name(),
            background = definition().background(),
            remediation = definition().remediation(),
            typeIndex = definition().typeIndex()
        )
    )
}

fun burp.api.montoya.http.message.HttpRequestResponse.toSerializableForm(): SerializableHttpRequestResponse {
    return SerializableHttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

fun ProxyHttpRequestResponse.toSerializableForm(): SerializableHttpRequestResponse {
    return SerializableHttpRequestResponse(
        request = request()?.toString() ?: "<no request>",
        response = response()?.toString() ?: "<no response>",
        notes = annotations().notes()
    )
}

private fun headersToString(msg: burp.api.montoya.http.message.HttpMessage): String? {
    return try { msg.headers().joinToString("\r\n") { "${it.name()}: ${it.value()}" } } catch (_: Exception) { null }
}

private fun bodyToStringOrNull(msg: burp.api.montoya.http.message.HttpMessage): String? {
    return try { msg.bodyToString().ifEmpty { null } } catch (_: Exception) { null }
}

fun ProxyHttpRequestResponse.toSerializableProxyForm(
    includeRequestBody: Boolean = true,
    includeResponseBody: Boolean = true,
    includeHeaders: Boolean = true,
    includeModifiedVersions: Boolean = false
): SerializableProxyHttpItem {
    val req = request()
    val finalReq = try { finalRequest() } catch (_: Exception) { null }
    val resp = response()
    val origResp = try { originalResponse() } catch (_: Exception) { null }
    val service = try { httpService() } catch (_: Exception) { null }

    val reqModified = try {
        req != null && finalReq != null && req.toString() != finalReq.toString()
    } catch (_: Exception) { false }

    val respModified = try {
        resp != null && origResp != null && resp.toString() != origResp.toString()
    } catch (_: Exception) { false }

    val wasEdited = try { edited() } catch (_: Exception) { false }

    return SerializableProxyHttpItem(
        id = id(),
        host = service?.host(),
        port = service?.port(),
        secure = service?.secure(),
        method = try { req?.method() } catch (_: Exception) { null },
        url = try { req?.url() } catch (_: Exception) { null },
        statusCode = try { resp?.statusCode()?.toInt() } catch (_: Exception) { null },
        mimeType = try { mimeType()?.name } catch (_: Exception) { null },
        requestHeaders = if (includeHeaders && req != null) headersToString(req) else null,
        requestBody = if (includeRequestBody && req != null) bodyToStringOrNull(req) else null,
        responseHeaders = if (includeHeaders && resp != null) headersToString(resp) else null,
        responseBody = if (includeResponseBody && resp != null) bodyToStringOrNull(resp) else null,
        requestModified = reqModified,
        responseModified = respModified,
        edited = wasEdited,
        finalRequestHeaders = if (includeModifiedVersions && reqModified && includeHeaders && finalReq != null)
            headersToString(finalReq) else null,
        finalRequestBody = if (includeModifiedVersions && reqModified && includeRequestBody && finalReq != null)
            bodyToStringOrNull(finalReq) else null,
        originalResponseHeaders = if (includeModifiedVersions && respModified && includeHeaders && origResp != null)
            headersToString(origResp) else null,
        originalResponseBody = if (includeModifiedVersions && respModified && includeResponseBody && origResp != null)
            bodyToStringOrNull(origResp) else null,
        notes = annotations()?.notes()
    )
}

fun ProxyWebSocketMessage.toSerializableForm(): SerializableWebSocketMessage {
    return SerializableWebSocketMessage(
        payload = payload()?.toString() ?: "<no payload>",
        direction = if (direction() == Direction.CLIENT_TO_SERVER)
            WebSocketMessageDirection.CLIENT_TO_SERVER
        else
            WebSocketMessageDirection.SERVER_TO_CLIENT,
        notes = annotations().notes()
    )
}

fun CollaboratorInteraction.toSerializableForm(): CollaboratorInteractionDetails {
    return CollaboratorInteractionDetails(
        id = id().toString(),
        type = type().name,
        timestamp = timeStamp().toString(),
        clientIp = clientIp().hostAddress,
        clientPort = clientPort(),
        customData = customData().orElse(null),
        dnsDetails = dnsDetails().orElse(null)?.let {
            CollaboratorDnsDetails(queryType = it.queryType().name)
        },
        httpDetails = httpDetails().orElse(null)?.let {
            CollaboratorHttpDetails(
                protocol = it.protocol().name,
                request = it.requestResponse()?.request()?.toString(),
                response = it.requestResponse()?.response()?.toString()
            )
        },
        smtpDetails = smtpDetails().orElse(null)?.let {
            CollaboratorSmtpDetails(
                protocol = it.protocol().name,
                conversation = it.conversation()
            )
        }
    )
}

// Serializable models

@Serializable
data class IssueDetails(
    val name: String?,
    val detail: String?,
    val remediation: String?,
    val httpService: SerializableHttpService?,
    val baseUrl: String?,
    val severity: AuditIssueSeverity,
    val confidence: AuditIssueConfidence,
    val requestResponses: List<SerializableHttpRequestResponse>,
    val collaboratorInteractions: List<SerializableInteraction>,
    val definition: SerializableAuditIssueDefinition
)

@Serializable
data class SerializableHttpService(
    val host: String,
    val port: Int,
    val secure: Boolean
)

@Serializable
enum class AuditIssueSeverity {
    HIGH, MEDIUM, LOW, INFORMATION, FALSE_POSITIVE
}

@Serializable
enum class AuditIssueConfidence {
    CERTAIN, FIRM, TENTATIVE
}

@Serializable
data class SerializableHttpRequestResponse(
    val request: String?,
    val response: String?,
    val notes: String?
)

@Serializable
data class SerializableProxyHttpItem(
    val id: Int,
    val host: String?,
    val port: Int?,
    val secure: Boolean?,
    val method: String?,
    val url: String?,
    val statusCode: Int?,
    val mimeType: String?,
    // request() = original request from client; response() = final response delivered to client
    val requestHeaders: String?,
    val requestBody: String?,
    val responseHeaders: String?,
    val responseBody: String?,
    // Modification flags — true means the request/response was changed between proxy stages
    val requestModified: Boolean,
    val responseModified: Boolean,
    val edited: Boolean,
    // Only present when requestModified=true: the final request actually sent to the server
    val finalRequestHeaders: String? = null,
    val finalRequestBody: String? = null,
    // Only present when responseModified=true: the original response received from the server
    val originalResponseHeaders: String? = null,
    val originalResponseBody: String? = null,
    val notes: String?
)

@Serializable
data class SerializableInteraction(
    val interactionId: String,
    val timestamp: String
)

@Serializable
data class SerializableAuditIssueDefinition(
    val id: String,
    val background: String?,
    val remediation: String?,
    val typeIndex: Int
)

@Serializable
enum class WebSocketMessageDirection {
    CLIENT_TO_SERVER, SERVER_TO_CLIENT
}

@Serializable
data class SerializableWebSocketMessage(
    val payload: String?,
    val direction: WebSocketMessageDirection,
    val notes: String?
)

@Serializable
data class CollaboratorInteractionDetails(
    val id: String,
    val type: String,
    val timestamp: String,
    val clientIp: String,
    val clientPort: Int,
    val customData: String?,
    val dnsDetails: CollaboratorDnsDetails?,
    val httpDetails: CollaboratorHttpDetails?,
    val smtpDetails: CollaboratorSmtpDetails?
)

@Serializable
data class CollaboratorDnsDetails(
    val queryType: String
)

@Serializable
data class CollaboratorHttpDetails(
    val protocol: String,
    val request: String?,
    val response: String?
)

@Serializable
data class CollaboratorSmtpDetails(
    val protocol: String,
    val conversation: String
)
