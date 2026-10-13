package burp.mcp.tools

import burp.api.montoya.collaborator.Interaction as CollaboratorInteraction
import burp.api.montoya.proxy.ProxyHttpRequestResponse
import burp.api.montoya.proxy.ProxyWebSocketMessage
import burp.api.montoya.scanner.audit.issues.AuditIssue
import burp.api.montoya.websocket.Direction
import burp.mcp.history.McpRequestRecord
import burp.mcp.history.ProxyHandlerCapture
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

/**
 * Cap a body string at [maxChars] for list/browse views, appending a marker that records how many
 * characters were dropped. The result stays a JSON-valid string value (unlike chopping the whole
 * serialised object), so a large body never breaks the emitted JSON. A null
 * [maxChars] means "no cap" — used by the single-item and raw tools that must return full bytes.
 */
private fun capBody(body: String?, maxChars: Int?): String? {
    if (body == null || maxChars == null || body.length <= maxChars) return body
    val dropped = body.length - maxChars
    return body.substring(0, maxChars) + "…[+$dropped chars truncated — use get_proxy_http_history_item or _raw for full body]"
}

/** Split a raw HTTP message at the header/body separator into (head incl. start-line, body-or-null). */
private fun splitRaw(raw: String): Pair<String, String?> {
    val separator = raw.indexOf("\r\n\r\n")
    if (separator < 0) return raw to null
    return raw.substring(0, separator) to raw.substring(separator + 4).ifEmpty { null }
}

/** Header lines only (start-line dropped), matching [headersToString]'s shape of a header block. */
private fun headerLinesOnly(head: String): String? {
    val firstBreak = head.indexOf("\r\n")
    if (firstBreak < 0) return null
    return head.substring(firstBreak + 2).ifEmpty { null }
}

fun ProxyHttpRequestResponse.toSerializableProxyForm(
    includeRequestBody: Boolean = true,
    includeResponseBody: Boolean = true,
    includeHeaders: Boolean = true,
    includeModifiedVersions: Boolean = false,
    includeRaw: Boolean = false,
    // Per-body character cap for list/browse views. null = no cap (single-item / raw tools).
    maxBodyChars: Int? = null,
    // This item's request/response as other extensions' proxy handlers left it, when the live capturer saw it.
    capture: ProxyHandlerCapture? = null
): SerializableProxyHttpItem {
    val req = request()
    val finalReq = try { finalRequest() } catch (_: Exception) { null }
    val resp = response()
    val origResp = try { originalResponse() } catch (_: Exception) { null }
    val service = try { httpService() } catch (_: Exception) { null }

    val reqBodyBase = if (req != null) bodyToStringOrNull(req) else null
    val respBodyBase = if (resp != null) bodyToStringOrNull(resp) else null

    // A live capture overrides the Montoya history value, which reads back as the as-received bytes even
    // when an extension rewrote the message in its proxy handlers (montoya-api #127). A capture identical
    // to the history value changes nothing, so the Montoya value stands. Mapping, as Burp presents these
    // items: the captured REQUEST is the "modified/final request" variant, the captured RESPONSE is the
    // "original response" variant.
    val reqCap = capture?.requestRaw?.let(::splitRaw)
    val respCap = capture?.responseRaw?.let(::splitRaw)

    val reqCaptureModified = reqCap != null && reqCap.second != reqBodyBase
    val respCaptureModified = respCap != null && respCap.second != respBodyBase

    val montoyaReqModified = try {
        req != null && finalReq != null && req.toString() != finalReq.toString()
    } catch (_: Exception) { false }

    val montoyaRespModified = try {
        resp != null && origResp != null && resp.toString() != origResp.toString()
    } catch (_: Exception) { false }

    val reqModified = reqCaptureModified || montoyaReqModified
    val respModified = respCaptureModified || montoyaRespModified

    // Effective modified/final request + original response: prefer the capture, else Montoya.
    val finalReqHeaders = when {
        reqCaptureModified -> headerLinesOnly(reqCap!!.first)
        montoyaReqModified && finalReq != null -> headersToString(finalReq)
        else -> null
    }
    val finalReqBody = when {
        reqCaptureModified -> reqCap!!.second
        montoyaReqModified && finalReq != null -> bodyToStringOrNull(finalReq)
        else -> null
    }
    val finalReqRaw = when {
        reqCaptureModified -> capture!!.requestRaw
        montoyaReqModified && finalReq != null -> try { finalReq.toString() } catch (_: Exception) { null }
        else -> null
    }
    val origRespHeaders = when {
        respCaptureModified -> headerLinesOnly(respCap!!.first)
        montoyaRespModified && origResp != null -> headersToString(origResp)
        else -> null
    }
    val origRespBody = when {
        respCaptureModified -> respCap!!.second
        montoyaRespModified && origResp != null -> bodyToStringOrNull(origResp)
        else -> null
    }

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
        requestBody = if (includeRequestBody && req != null) capBody(reqBodyBase, maxBodyChars) else null,
        responseHeaders = if (includeHeaders && resp != null) headersToString(resp) else null,
        responseBody = if (includeResponseBody && resp != null) capBody(respBodyBase, maxBodyChars) else null,
        requestModified = reqModified,
        responseModified = respModified,
        edited = wasEdited,
        finalRequestHeaders = if (includeModifiedVersions && reqModified && includeHeaders) finalReqHeaders else null,
        finalRequestBody = if (includeModifiedVersions && reqModified && includeRequestBody)
            capBody(finalReqBody, maxBodyChars) else null,
        originalResponseHeaders = if (includeModifiedVersions && respModified && includeHeaders) origRespHeaders else null,
        originalResponseBody = if (includeModifiedVersions && respModified && includeResponseBody)
            capBody(origRespBody, maxBodyChars) else null,
        notes = annotations()?.notes(),
        // Full raw request bytes including the start-line (method/path/version), which the
        // split headers/body fields drop. Needed to round-trip a captured request faithfully.
        rawRequest = if (includeRaw && req != null) try { req.toString() } catch (_: Exception) { null } else null,
        rawFinalRequest = if (includeRaw && reqModified) finalReqRaw else null
    )
}

fun McpRequestRecord.toSerializableForm(
    includeRequestBody: Boolean = true,
    includeResponseBody: Boolean = true,
    includeHeaders: Boolean = true
): SerializableMcpRequestItem {
    val req = request
    val resp = response
    val service = try { req.httpService() } catch (_: Exception) { null }

    return SerializableMcpRequestItem(
        id = id,
        timestamp = timestamp,
        httpVersion = httpVersion,
        host = service?.host(),
        port = service?.port(),
        secure = service?.secure(),
        method = try { req.method() } catch (_: Exception) { null },
        url = try { req.url() } catch (_: Exception) { null },
        statusCode = try { resp?.statusCode()?.toInt() } catch (_: Exception) { null },
        mimeType = try { resp?.mimeType()?.name } catch (_: Exception) { null },
        requestLength = try { req.toByteArray().length() } catch (_: Exception) { null },
        responseLength = try { resp?.toByteArray()?.length() } catch (_: Exception) { null },
        requestHeaders = if (includeHeaders) headersToString(req) else null,
        requestBody = if (includeRequestBody) bodyToStringOrNull(req) else null,
        responseHeaders = if (includeHeaders && resp != null) headersToString(resp) else null,
        responseBody = if (includeResponseBody && resp != null) bodyToStringOrNull(resp) else null
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
    val notes: String?,
    // Full raw request bytes (incl. start-line). Only populated when includeRaw=true.
    val rawRequest: String? = null,
    val rawFinalRequest: String? = null
)

@Serializable
data class IntruderResult(
    val payload: String,
    val statusCode: Int? = null,
    val responseLength: Int? = null,
    val timingMs: Long? = null,
    val error: String? = null
)

@Serializable
data class SiteMapEntry(
    val url: String?,
    val method: String?,
    val statusCode: Int?,
    val mimeType: String?
)

@Serializable
data class SerializableMcpRequestItem(
    val id: Int,
    // Epoch milliseconds at which the MCP issued the request.
    val timestamp: Long,
    val httpVersion: String,
    val host: String?,
    val port: Int?,
    val secure: Boolean?,
    val method: String?,
    val url: String?,
    val statusCode: Int?,
    val mimeType: String?,
    // Full on-the-wire byte lengths (headers + body) as sent/received.
    val requestLength: Int?,
    val responseLength: Int?,
    val requestHeaders: String?,
    val requestBody: String?,
    val responseHeaders: String?,
    val responseBody: String?
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
