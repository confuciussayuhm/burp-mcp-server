package burp.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.mcp.approval.PendingApprovalManager
import burp.mcp.history.McpRequestHistory
import burp.mcp.intercept.InterceptManager
import burp.mcp.intercept.InterceptTab
import javax.swing.JTabbedPane
import javax.swing.SwingUtilities

class BurpMcpExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val interceptManager = InterceptManager(api)
        interceptManager.register()
        val approvals = PendingApprovalManager()
        val requestHistory = McpRequestHistory(api.persistence().extensionData())

        val server = McpServer(api, config, interceptManager, approvals, requestHistory)

        val tabbedPane = JTabbedPane()
        val serverTab = ServerTab(api, config, server, interceptManager, approvals)
        val interceptTab = InterceptTab(api, interceptManager)
        val requestLogTab = RequestLogTab(api, requestHistory)

        tabbedPane.addTab("Server", serverTab.component)
        val interceptIndex = tabbedPane.tabCount
        tabbedPane.addTab("Intercept", interceptTab.component)
        tabbedPane.addTab("Request Log", requestLogTab.component)

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
            approvals.removeListener(approvalsBadgeListener)
            serverTab.cleanup()
            server.stop()
            interceptManager.deregister()
            config.cleanup()
        }

        api.logging().logToOutput("MCP Server extension loaded")
    }
}
