package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.mcp.intercept.InterceptManager
import burp.mcp.tools.registerTools
import io.ktor.http.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.serialization.kotlinx.json.*
import io.modelcontextprotocol.kotlin.sdk.types.McpJson
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.cors.routing.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.modelcontextprotocol.kotlin.sdk.types.Implementation
import io.modelcontextprotocol.kotlin.sdk.types.ServerCapabilities
import io.modelcontextprotocol.kotlin.sdk.server.Server
import io.modelcontextprotocol.kotlin.sdk.server.ServerOptions
import io.modelcontextprotocol.kotlin.sdk.server.mcpStreamableHttp
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

enum class ServerState { Stopped, Starting, Running, Stopping, Failed }

class McpServer(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val interceptManager: InterceptManager
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

                    install(CORS) {
                        anyHost()

                        allowMethod(HttpMethod.Get)
                        allowMethod(HttpMethod.Post)

                        allowHeader(HttpHeaders.ContentType)
                        allowHeader(HttpHeaders.Accept)
                        allowHeader("Last-Event-ID")

                        allowCredentials = false
                        allowNonSimpleContentTypes = true
                        maxAgeInSeconds = 3600
                    }

                    mcpStreamableHttp {
                        Server(
                            serverInfo = Implementation("burp-mcp-server", "1.0.0"),
                            options = ServerOptions(
                                capabilities = ServerCapabilities(
                                    tools = ServerCapabilities.Tools(listChanged = false)
                                )
                            )
                        ).also { it.registerTools(api, config, interceptManager) }
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
