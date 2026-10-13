package burp.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.mcp.approval.ApprovalPolicy
import burp.mcp.approval.PendingApprovalManager
import burp.mcp.collab.CollaboratorBroker
import burp.mcp.history.McpRequestHistory
import burp.mcp.history.ProxyHandlerCaptureStore
import burp.mcp.history.ProxyHandlerCapturer
import burp.mcp.intercept.InterceptManager
import burp.mcp.intercept.InterceptTab
import burp.mcp.session.KeepAliveManager
import burp.mcp.session.SessionInjector
import burp.mcp.session.SessionStore
import burp.mcp.session.SessionsTab
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

class BurpMcpExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val interceptManager = InterceptManager(api)
        interceptManager.register()
        val approvals = PendingApprovalManager()
        val policy = ApprovalPolicy(api, config, approvals)
        val requestHistory = McpRequestHistory(api.persistence().extensionData())
        val sessionStore = SessionStore(api.persistence().extensionData())
        val keepAliveManager = KeepAliveManager(api, sessionStore)
        keepAliveManager.start()
        val sessionInjector = SessionInjector(api, sessionStore)
        api.http().registerHttpHandler(sessionInjector)
        sessionInjector.start()

        // Capture each proxy message as other extensions' proxy handlers leave it. proxy().history()
        // reads back the as-received bytes (montoya-api #127), so without this a body rewritten by
        // another extension is invisible to the proxy-history tools.
        val handlerCaptures = ProxyHandlerCaptureStore()
        val handlerCapturer = ProxyHandlerCapturer(api, handlerCaptures)
        handlerCapturer.register()

        // One Collaborator client for the whole extension load. The MCP transport is stateless and
        // re-registers tools per request, so anything the collaborator tools need to remember between
        // calls has to be owned out here.
        val collaborator = CollaboratorBroker(api, api.persistence().extensionData())

        val server = McpServer(api, config, interceptManager, policy, requestHistory, sessionStore, collaborator, handlerCaptures)

        val tabbedPane = JTabbedPane()
        val serverTab = ServerTab(api, config, server, interceptManager, approvals, policy)
        val interceptTab = InterceptTab(api, interceptManager)
        val requestLogTab = RequestLogTab(api, requestHistory)
        val sessionsTab = SessionsTab(sessionStore)

        tabbedPane.addTab("Server", serverTab.component)
        val interceptIndex = tabbedPane.tabCount
        tabbedPane.addTab("Intercept", interceptTab.component)
        tabbedPane.addTab("Request Log", requestLogTab.component)
        tabbedPane.addTab("Sessions", sessionsTab.component)

        fun setBadge(index: Int, base: String, count: Int) {
            tabbedPane.setTitleAt(index, if (count > 0) "$base ($count)" else base)
        }

        // Server tab badge reflects pending approvals (the surface that handles them).
        val approvalsBadgeListener: () -> Unit = {
            SwingUtilities.invokeLater { setBadge(0, "Server", approvals.store.size()) }
        }
        approvals.addListener(approvalsBadgeListener)
        setBadge(0, "Server", approvals.store.size())

        val interceptBadgeTimer = javax.swing.Timer(1000) {
            setBadge(interceptIndex, "Intercept", interceptManager.store.size())
        }
        interceptBadgeTimer.start()
        setBadge(interceptIndex, "Intercept", interceptManager.store.size())

        api.userInterface().registerSuiteTab("MCP", tabbedPane)
        api.userInterface().registerContextMenuItemsProvider(AutoApproveContextMenu(config))

        if (config.enabled) {
            server.start()
        }

        api.extension().registerUnloadingHandler {
            interceptBadgeTimer.stop()
            interceptTab.cleanup()
            requestLogTab.cleanup()
            sessionsTab.cleanup()
            approvals.removeListener(approvalsBadgeListener)
            serverTab.cleanup()
            sessionInjector.stop()
            handlerCapturer.deregister()
            keepAliveManager.stop()
            // shutdown(), not stop(): stop() leaves the server's single-thread executor alive, so
            // every extension reload leaked a thread.
            server.shutdown()
            interceptManager.deregister()
            config.cleanup()
        }

        api.logging().logToOutput("MCP Server extension loaded")
    }
}
