package burp.mcp

import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.ui.contextmenu.ContextMenuEvent
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider
import java.awt.Component
import javax.swing.JMenu
import javax.swing.JMenuItem
import javax.swing.JSeparator

class AutoApproveContextMenu(private val config: McpConfig) : ContextMenuItemsProvider {

    private data class Target(val host: String, val port: Int)

    override fun provideMenuItems(event: ContextMenuEvent): List<Component> {
        val requestResponses = mutableListOf<HttpRequestResponse>()
        requestResponses.addAll(event.selectedRequestResponses())
        event.messageEditorRequestResponse().ifPresent { editor ->
            requestResponses.add(editor.requestResponse())
        }

        val targets = requestResponses.mapNotNull { rr ->
            try {
                val service = rr.httpService()
                Target(service.host(), service.port())
            } catch (_: Exception) {
                null
            }
        }.distinct()

        if (targets.isEmpty()) return emptyList()

        val menu = JMenu("MCP: Auto-approve target")

        if (targets.size == 1) {
            val t = targets[0]
            menu.add(JMenuItem("Add ${t.host}:${t.port}").apply {
                addActionListener { config.addAutoApproveTarget("${t.host}:${t.port}") }
            })
            menu.add(JMenuItem("Add ${t.host} (any port)").apply {
                addActionListener { config.addAutoApproveTarget(t.host) }
            })
        } else {
            val capped = targets.take(20)

            menu.add(JMenuItem("Add all ${targets.size} targets (host:port)").apply {
                addActionListener {
                    targets.forEach { t -> config.addAutoApproveTarget("${t.host}:${t.port}") }
                }
            })
            menu.add(JSeparator())
            capped.forEach { t ->
                menu.add(JMenuItem("Add ${t.host}:${t.port}").apply {
                    addActionListener { config.addAutoApproveTarget("${t.host}:${t.port}") }
                })
            }
            if (targets.size > 20) {
                menu.add(JMenuItem("...and ${targets.size - 20} more").apply { isEnabled = false })
            }
        }

        return listOf(menu)
    }
}
