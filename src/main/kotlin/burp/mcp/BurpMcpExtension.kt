package burp.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.mcp.approval.PendingApprovalManager
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

        val server = McpServer(api, config, interceptManager, approvals)
        val tab = ConfigTab(api, config, server, interceptManager)
        val interceptTab = InterceptTab(api, interceptManager)
        val approvalsTab = ApprovalsTab(api, config, approvals)

        val tabbedPane = tab.component as JTabbedPane
        tabbedPane.addTab("Intercept", interceptTab.component)
        val approvalsIndex = tabbedPane.tabCount
        tabbedPane.addTab("Approvals", approvalsTab.component)

        fun updateApprovalsTitle() {
            val count = approvals.store.size()
            tabbedPane.setTitleAt(approvalsIndex, if (count > 0) "Approvals ($count)" else "Approvals")
        }
        val approvalsTitleListener: () -> Unit = {
            SwingUtilities.invokeLater { updateApprovalsTitle() }
        }
        approvals.addListener(approvalsTitleListener)
        updateApprovalsTitle()

        api.userInterface().registerSuiteTab("MCP", tabbedPane)
        api.userInterface().registerContextMenuItemsProvider(AutoApproveContextMenu(config))

        if (config.enabled) {
            server.start()
        }

        api.extension().registerUnloadingHandler {
            interceptTab.cleanup()
            approvalsTab.cleanup()
            approvals.removeListener(approvalsTitleListener)
            tab.cleanup()
            server.stop()
            interceptManager.deregister()
            config.cleanup()
        }

        api.logging().logToOutput("MCP Server extension loaded")
    }
}
