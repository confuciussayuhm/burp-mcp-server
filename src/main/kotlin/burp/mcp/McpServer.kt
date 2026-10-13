package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.mcp.collab.CollaboratorBroker
import burp.mcp.history.McpRequestHistory
import burp.mcp.history.ProxyHandlerCaptureStore
import burp.mcp.intercept.InterceptManager
import burp.mcp.session.SessionStore
import burp.mcp.tools.registerTools
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.serialization.kotlinx.json.*
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStatelessStreamableHttp
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

enum class ServerState { Stopped, Starting, Running, Stopping, Failed }

/**
 * Refuses anything a web browser sent. Browsers put an Origin header on every POST — cross-site,
 * same-site and DNS-rebinding ones alike — while MCP clients such as Claude Code send none. Without
 * this, any page open in the browser could drive Burp: a rebinding page counts as same-origin, so
 * withholding CORS alone does not stop it. The SDK's own allowedOrigins check is no use here: it
 * also rejects a MISSING Origin, which would lock out every non-browser client.
 */
internal fun Application.rejectBrowserRequests(onRejected: (origin: String) -> Unit) {
    intercept(ApplicationCallPipeline.Plugins) {
        val origin = call.request.headers[HttpHeaders.Origin] ?: return@intercept
        onRejected(origin)
        call.respondText(
            """{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"Browser requests are not accepted"}}""",
            ContentType.Application.Json,
            HttpStatusCode.Forbidden
        )
        finish()
    }
}

class McpServer(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val interceptManager: InterceptManager,
    private val requestHistory: McpRequestHistory,
    private val sessionStore: SessionStore,
    private val collaborator: CollaboratorBroker,
    private val handlerCaptures: ProxyHandlerCaptureStore
) {

    private var server: EmbeddedServer<*, *>? = null
    private val executor: ExecutorService = Executors.newSingleThreadExecutor()

    @Volatile
    var state: ServerState = ServerState.Stopped
        private set

    var stateListener: ((ServerState) -> Unit)? = null

    private fun setState(newState: ServerState) {
        state = newState
        stateListener?.invoke(newState)
    }

    fun start() {
        setState(ServerState.Starting)

        executor.submit {
            try {
                server?.stop(1000, 5000)
                server = null

                server = embeddedServer(Netty, port = config.port, host = config.host) {
                    install(ContentNegotiation) {
                        json(McpJson)
                    }

                    rejectBrowserRequests { origin ->
                        api.logging().logToOutput("MCP server refused a browser request (Origin: $origin)")
                    }

                    mcpStatelessStreamableHttp {
                        Server(
                            serverInfo = Implementation("burp-mcp-server", "1.0.0"),
                            options = ServerOptions(
                                capabilities = ServerCapabilities(
                                    tools = ServerCapabilities.Tools(listChanged = false)
                                )
                            )
                        ).also { it.registerTools(api, interceptManager, requestHistory, sessionStore, collaborator, handlerCaptures) }
                    }

                    routing {
                        get("/.well-known/oauth-authorization-server") {
                            call.respondText(
                                """{"error": "not_found"}""",
                                ContentType.Application.Json,
                                HttpStatusCode.NotFound
                            )
                        }
                        get("/.well-known/oauth-protected-resource") {
                            call.respondText(
                                """{"error": "not_found"}""",
                                ContentType.Application.Json,
                                HttpStatusCode.NotFound
                            )
                        }
                    }
                }.apply {
                    start(wait = false)
                }

                api.logging().logToOutput("Started MCP server on ${config.host}:${config.port}")
                setState(ServerState.Running)
            } catch (e: Exception) {
                api.logging().logToError(e)
                setState(ServerState.Failed)
            }
        }
    }

    fun stop() {
        setState(ServerState.Stopping)

        try {
            server?.stop(1000, 5000)
            server = null
            api.logging().logToOutput("Stopped MCP server")
        } catch (e: Exception) {
            api.logging().logToError(e)
        }

        setState(ServerState.Stopped)
    }

    fun shutdown() {
        stop()
        executor.shutdown()
        executor.awaitTermination(10, TimeUnit.SECONDS)
    }

}
