package burp.mcp

import burp.api.montoya.BurpExtension
import burp.api.montoya.MontoyaApi
import burp.mcp.intercept.InterceptManager
import burp.mcp.intercept.InterceptTab
import javax.swing.JTabbedPane

class BurpMcpExtension : BurpExtension {

    override fun initialize(api: MontoyaApi) {
        api.extension().setName("MCP Server")

        val config = McpConfig(api.persistence().extensionData(), api.logging())
        val interceptManager = InterceptManager(api)
        interceptManager.register()

        val server = McpServer(api, config, interceptManager)
        val tab = ConfigTab(api, config, server, interceptManager)
        val interceptTab = InterceptTab(api, interceptManager)

        val tabbedPane = tab.component as JTabbedPane
        tabbedPane.addTab("Intercept", interceptTab.component)

        api.userInterface().registerSuiteTab("MCP", tabbedPane)

        if (config.enabled) {
            server.start()
        }

        api.extension().registerUnloadingHandler {
            interceptTab.cleanup()
            tab.cleanup()
            server.stop()
            interceptManager.deregister()
            config.cleanup()
        }

        api.logging().logToOutput("MCP Server extension loaded")
    }
}
