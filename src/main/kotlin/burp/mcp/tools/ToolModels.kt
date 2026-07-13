package burp.mcp.tools

import burp.api.montoya.http.HttpService
import kotlinx.serialization.Serializable

interface HttpServiceParams {
    val targetHostname: String
    val targetPort: Int
    val usesHttps: Boolean

    fun toMontoyaService(): HttpService = HttpService.httpService(targetHostname, targetPort, usesHttps)
}

// HTTP Requests
@Serializable
data class SendHttp1Request(
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendHttp2Request(
    val pseudoHeaders: Map<String, String>,
    val headers: Map<String, String>,
    val requestBody: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

// Burp Integration
@Serializable
data class CreateRepeaterTab(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

@Serializable
data class SendToIntruder(
    val tabName: String?,
    val content: String,
    override val targetHostname: String,
    override val targetPort: Int,
    override val usesHttps: Boolean
) : HttpServiceParams

// Encoding
@Serializable
data class UrlEncode(val content: String)

@Serializable
data class UrlDecode(val content: String)

@Serializable
data class Base64Encode(val content: String)

@Serializable
data class Base64Decode(val content: String)

@Serializable
data class GenerateRandomString(val length: Int, val characterSet: String)

// Config
@Serializable
data class SetProjectOptions(val json: String)

@Serializable
data class SetUserOptions(val json: String)

// Proxy & Scanner
@Serializable
data class SetTaskExecutionEngineState(val running: Boolean)

@Serializable
data class SetProxyInterceptState(val intercepting: Boolean)

@Serializable
data class SetActiveEditorContents(val text: String)

// History (paginated)
@Serializable
data class GetScannerIssues(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyHttpHistory(
    override val count: Int,
    override val offset: Int,
    val includeRequestBody: Boolean? = null,
    val includeResponseBody: Boolean? = null,
    val includeHeaders: Boolean? = null,
    val statusCodes: String? = null,
    val methods: String? = null,
    val host: String? = null,
    val mimeTypes: String? = null,
    val inScopeOnly: Boolean? = null
) : Paginated

@Serializable
data class GetProxyHttpHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val includeRequestBody: Boolean? = null,
    val includeResponseBody: Boolean? = null,
    val includeHeaders: Boolean? = null,
    val statusCodes: String? = null,
    val methods: String? = null,
    val host: String? = null,
    val mimeTypes: String? = null,
    val inScopeOnly: Boolean? = null
) : Paginated

@Serializable
data class GetProxyHttpHistoryItem(val id: Int)

@Serializable
data class GetMcpRequestHistory(
    override val count: Int,
    override val offset: Int,
    val includeRequestBody: Boolean? = null,
    val includeResponseBody: Boolean? = null,
    val includeHeaders: Boolean? = null,
    val statusCodes: String? = null,
    val methods: String? = null,
    val host: String? = null,
    val mimeTypes: String? = null,
    val inScopeOnly: Boolean? = null
) : Paginated

@Serializable
data class GetMcpRequestHistoryRegex(
    val regex: String,
    override val count: Int,
    override val offset: Int,
    val includeRequestBody: Boolean? = null,
    val includeResponseBody: Boolean? = null,
    val includeHeaders: Boolean? = null,
    val statusCodes: String? = null,
    val methods: String? = null,
    val host: String? = null,
    val mimeTypes: String? = null,
    val inScopeOnly: Boolean? = null
) : Paginated

@Serializable
data class GetMcpRequestHistoryItem(val id: Int)

@Serializable
data class GetProxyWebsocketHistory(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetProxyWebsocketHistoryRegex(val regex: String, override val count: Int, override val offset: Int) : Paginated

// Professional Edition
@Serializable
data class GenerateCollaboratorPayload(val customData: String? = null)

@Serializable
data class GetCollaboratorInteractions(val payloadId: String? = null)

// Intercept
@Serializable
data class SetMcpInterceptEnabled(val enabled: Boolean)

@Serializable
data class GetInterceptedRequests(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetInterceptedResponses(override val count: Int, override val offset: Int) : Paginated

@Serializable
data class GetInterceptedMessageDetail(val messageId: String)

@Serializable
data class Replacement(val find: String, val replace: String)

@Serializable
data class ForwardInterceptedMessage(
    val messageId: String,
    val modifiedRaw: String? = null,
    val replacements: List<Replacement>? = null
)

@Serializable
data class DropInterceptedMessage(val messageId: String)

// Capture -> mutate -> replay

/** One parameter mutation for replay. `type` is one of: url, body, cookie. */
@Serializable
data class ParamUpdate(val type: String, val name: String, val value: String)

@Serializable
data class ReplayProxyHistoryItem(
    val id: Int,
    val replacements: List<Replacement>? = null,
    val setHeaders: Map<String, String>? = null,
    val updateParams: List<ParamUpdate>? = null,
    val setBody: String? = null,
    val setPath: String? = null,
    val setMethod: String? = null,
    val retargetHost: String? = null,
    val retargetPort: Int? = null,
    val retargetTls: Boolean? = null,
    // AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN
    val httpMode: String? = null,
    val sni: String? = null,
    // ALWAYS | NEVER | SAME_HOST | IN_SCOPE
    val redirectionMode: String? = null,
    val responseTimeoutMs: Long? = null
)

@Serializable
data class GetProxyHttpHistoryItemRaw(val id: Int)

@Serializable
data class IntruderBatch(
    val baseId: Int? = null,
    val baseContent: String? = null,
    val targetHostname: String? = null,
    val targetPort: Int? = null,
    val usesHttps: Boolean? = null,
    // The literal marker string in the base request that each payload replaces.
    val marker: String,
    val payloads: List<String>,
    // AUTO | HTTP_1 | HTTP_2 | HTTP_2_IGNORE_ALPN
    val httpMode: String? = null,
    val throttleMs: Int? = null
)

@Serializable
data class GetSiteMap(
    override val count: Int,
    override val offset: Int,
    val prefix: String? = null
) : Paginated
