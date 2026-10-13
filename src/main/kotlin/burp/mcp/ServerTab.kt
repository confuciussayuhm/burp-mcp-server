package burp.mcp

import burp.mcp.intercept.InterceptManager
import burp.mcp.ui.UiKit
import java.awt.BorderLayout
import java.awt.Component
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.net.Inet4Address
import java.net.NetworkInterface
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.event.PopupMenuEvent
import javax.swing.event.PopupMenuListener

/** Server status, bind address and connect snippets, plus the agent intercept switch. */
class ServerTab(
    private val config: McpConfig,
    private val server: McpServer,
    private val interceptManager: InterceptManager
) {

    val component: Component by lazy { onEdt { buildUi() } }

    private var pendingCountTimer: javax.swing.Timer? = null

    fun cleanup() {
        pendingCountTimer?.stop()
        pendingCountTimer = null
        server.stateListener = null
    }

    private fun <T> onEdt(block: () -> T): T {
        if (SwingUtilities.isEventDispatchThread()) return block()
        var result: T? = null
        var failure: Throwable? = null
        SwingUtilities.invokeAndWait {
            try {
                result = block()
            } catch (t: Throwable) {
                failure = t
            }
        }
        failure?.let { throw it }
        @Suppress("UNCHECKED_CAST")
        return result as T
    }

    private fun detectNetworkInterfaces(): List<String> {
        val entries = mutableListOf(
            "0.0.0.0 (All interfaces)",
            "127.0.0.1 (Loopback)"
        )
        try {
            for (iface in NetworkInterface.getNetworkInterfaces()) {
                if (!iface.isUp) continue
                for (addr in iface.inetAddresses) {
                    if (addr is Inet4Address) {
                        val ip = addr.hostAddress
                        if (ip != "127.0.0.1") {
                            entries.add("$ip (${iface.displayName})")
                        }
                    }
                }
            }
        } catch (_: Exception) {
        }
        return entries
    }

    private fun extractIp(display: String): String {
        val space = display.indexOf(' ')
        return if (space > 0) display.substring(0, space) else display
    }

    private fun connectCommand(): String =
        "claude mcp add --transport http burp http://${config.host}:${config.port}/mcp"

    private fun connectJson(): String =
        """{
  "mcpServers": {
    "burp": {
      "type": "http",
      "url": "http://${config.host}:${config.port}/mcp"
    }
  }
}"""

    private fun buildUi(): JPanel {
        val serverCard = buildServerCard()
        val interceptCard = buildInterceptCard()

        val stack = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            listOf(serverCard, interceptCard).forEachIndexed { i, card ->
                if (i > 0) add(Box.createVerticalStrut(UiKit.GAP_NORM))
                card.alignmentX = JPanel.LEFT_ALIGNMENT
                add(card)
            }
            add(Box.createVerticalGlue())
        }

        val contentRoot = JPanel(BorderLayout()).apply {
            border = EmptyBorder(
                UiKit.PAD_OUTER.top,
                UiKit.PAD_OUTER.left,
                UiKit.PAD_OUTER.bottom,
                UiKit.PAD_OUTER.right
            )
            add(stack, BorderLayout.NORTH)
        }

        val scroll = JScrollPane(contentRoot).apply {
            border = BorderFactory.createEmptyBorder()
            verticalScrollBar.unitIncrement = 16
        }

        return JPanel(BorderLayout()).apply {
            add(scroll, BorderLayout.CENTER)
        }
    }

    private fun buildServerCard(): JPanel {
        val statusHolder = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(UiKit.statusDot(statusOf(server.state), 12), BorderLayout.CENTER)
        }
        val statusText = JLabel(server.state.toString()).apply { font = UiKit.fontHeader() }
        val urlLabel = JLabel(currentUrl()).apply {
            font = UiKit.fontCode()
            foreground = UiKit.captionFg()
        }
        val copyFeedback = JLabel(" ").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.captionFg()
        }

        val copy = UiKit.copyButton(
            primaryLabel = "Copy connect command",
            primarySupplier = { connectCommand() },
            extras = listOf("Copy .mcp.json snippet" to { connectJson() }),
            feedback = { UiKit.ephemeral(copyFeedback, "Copied — $it", 1500) }
        )

        val statusRow = JPanel(GridBagLayout()).apply { isOpaque = false }
        run {
            val gbc = GridBagConstraints().apply {
                insets = Insets(0, 0, 0, UiKit.GAP_NORM)
                anchor = GridBagConstraints.WEST
            }
            gbc.gridx = 0; gbc.gridy = 0
            statusRow.add(statusHolder, gbc)
            gbc.gridx = 1
            statusRow.add(statusText, gbc)
            gbc.gridx = 2; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
            statusRow.add(JLabel(""), gbc)
            gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE
            gbc.gridx = 3
            statusRow.add(urlLabel, gbc)
            gbc.gridx = 4; gbc.insets = Insets(0, UiKit.GAP_WIDE, 0, 0)
            statusRow.add(copy, gbc)
        }

        val hostComboBox = JComboBox<String>().apply {
            isEditable = true
            detectNetworkInterfaces().forEach { addItem(it) }
            val match = (0 until itemCount).map { getItemAt(it) }.firstOrNull { extractIp(it) == config.host }
            selectedItem = match ?: config.host
        }
        hostComboBox.addPopupMenuListener(object : PopupMenuListener {
            override fun popupMenuWillBecomeVisible(e: PopupMenuEvent) {
                val current = (hostComboBox.editor.item as? String)
                    ?: (hostComboBox.selectedItem as? String) ?: ""
                hostComboBox.removeAllItems()
                detectNetworkInterfaces().forEach { hostComboBox.addItem(it) }
                val match = (0 until hostComboBox.itemCount)
                    .map { hostComboBox.getItemAt(it) }
                    .firstOrNull { extractIp(it) == extractIp(current) }
                hostComboBox.selectedItem = match ?: current
            }
            override fun popupMenuWillBecomeInvisible(e: PopupMenuEvent) {}
            override fun popupMenuCanceled(e: PopupMenuEvent) {}
        })

        val portField = JTextField(config.port.toString(), 6)
        val enableCheckbox = JCheckBox("Enabled", config.enabled)
        val portError = JLabel(" ").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.color(UiKit.Status.FAILED)
        }

        fun applyConfig(): Boolean {
            val rawSelection = (hostComboBox.editor.item as? String)
                ?: (hostComboBox.selectedItem as? String)
                ?: "127.0.0.1"
            val newHost = extractIp(rawSelection)
            val newPort = portField.text.trim().toIntOrNull()
            if (newPort == null || newPort !in 1..65535) {
                UiKit.ephemeral(portError, "Port must be between 1 and 65535", 3000)
                portField.requestFocusInWindow()
                portField.selectAll()
                return false
            }
            config.host = newHost
            config.port = newPort
            urlLabel.text = currentUrl()
            return true
        }

        fun applyAndRestartIfNeeded() {
            if (!applyConfig()) return
            if (config.enabled) {
                server.stop()
                server.start()
            }
        }

        enableCheckbox.addActionListener {
            config.enabled = enableCheckbox.isSelected
            if (config.enabled) {
                if (!applyConfig()) {
                    config.enabled = false
                    enableCheckbox.isSelected = false
                    return@addActionListener
                }
                server.start()
            } else {
                server.stop()
            }
        }
        hostComboBox.addActionListener { applyAndRestartIfNeeded() }
        portField.addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) {
                applyAndRestartIfNeeded()
            }
        })
        portField.addActionListener { applyAndRestartIfNeeded() }

        server.stateListener = { state ->
            SwingUtilities.invokeLater {
                statusText.text = state.toString()
                urlLabel.text = currentUrl()
                statusHolder.removeAll()
                statusHolder.add(UiKit.statusDot(statusOf(state), 12), BorderLayout.CENTER)
                statusHolder.revalidate()
                statusHolder.repaint()
            }
        }

        val formRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_NORM, 0)).apply {
            isOpaque = false
            add(JLabel("Host").apply { font = UiKit.fontBody() })
            add(hostComboBox)
            add(UiKit.spacer(UiKit.GAP_WIDE))
            add(JLabel("Port").apply { font = UiKit.fontBody() })
            add(portField)
            add(UiKit.spacer(UiKit.GAP_WIDE))
            add(enableCheckbox)
        }

        val card = UiKit.card()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = EmptyBorder(
            UiKit.PAD_CARD.top, UiKit.PAD_CARD.left, UiKit.PAD_CARD.bottom, UiKit.PAD_CARD.right
        )
        listOf(statusRow, formRow, copyFeedback, portError).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }
        card.add(statusRow)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(formRow)
        card.add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
        card.add(copyFeedback)
        card.add(portError)
        return card
    }

    private fun buildInterceptCard(): JPanel {
        val state = interceptManager.isEnabled()
        val dotHolder = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(UiKit.statusDot(if (state) UiKit.Status.RUNNING else UiKit.Status.STOPPED, 12), BorderLayout.CENTER)
        }
        val statusText = JLabel(if (state) "Enabled" else "Disabled").apply { font = UiKit.fontHeader() }
        val pendingLabel = JLabel("Pending: ${interceptManager.store.size()}").apply { font = UiKit.fontBody() }
        val forwardAll = JButton("Forward All & Disable").apply { isEnabled = state }
        val header = UiKit.sectionLabel("Agent intercept")
        // Short label, detail in the tooltip: a full sentence in a non-wrapping JLabel sets the
        // preferred width of the whole tab and forces a horizontal scrollbar.
        val caption = UiKit.caption("Holds Burp Proxy traffic for the MCP client to forward, edit or drop")
        val toggle = JCheckBox("Hold proxy traffic for the agent", state).apply {
            toolTipText = "<html>Requests and responses passing through Burp Proxy wait in the Agent Intercept tab<br>" +
                "until the MCP client — or you — forwards, edits or drops them.<br>" +
                "Separate from Burp's own Proxy → Intercept. The MCP connection itself is never intercepted.</html>"
        }

        fun refresh(enabled: Boolean) {
            statusText.text = if (enabled) "Enabled" else "Disabled"
            forwardAll.isEnabled = enabled
            toggle.isSelected = enabled
            dotHolder.removeAll()
            dotHolder.add(UiKit.statusDot(if (enabled) UiKit.Status.RUNNING else UiKit.Status.STOPPED, 12), BorderLayout.CENTER)
            dotHolder.revalidate()
            dotHolder.repaint()
        }
        interceptManager.addStateListener { enabled ->
            SwingUtilities.invokeLater { refresh(enabled) }
        }
        toggle.addActionListener {
            if (toggle.isSelected) interceptManager.enable() else interceptManager.disable()
        }
        forwardAll.addActionListener { interceptManager.disable() }

        pendingCountTimer = javax.swing.Timer(1000) {
            pendingLabel.text = "Pending: ${interceptManager.store.size()}"
        }.apply { start() }

        val statusRow = JPanel(GridBagLayout()).apply { isOpaque = false }
        val gbc = GridBagConstraints().apply {
            insets = Insets(0, 0, 0, UiKit.GAP_NORM)
            anchor = GridBagConstraints.WEST
        }
        gbc.gridx = 0; gbc.gridy = 0
        statusRow.add(dotHolder, gbc)
        gbc.gridx = 1
        statusRow.add(statusText, gbc)
        gbc.gridx = 2
        statusRow.add(UiKit.spacer(UiKit.GAP_WIDE), gbc)
        gbc.gridx = 3
        statusRow.add(pendingLabel, gbc)
        gbc.gridx = 4; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
        statusRow.add(JLabel(""), gbc)
        gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE
        gbc.gridx = 5
        statusRow.add(forwardAll, gbc)

        val card = UiKit.card()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = EmptyBorder(
            UiKit.PAD_CARD.top, UiKit.PAD_CARD.left, UiKit.PAD_CARD.bottom, UiKit.PAD_CARD.right
        )
        listOf(header, caption, statusRow, toggle).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }
        card.add(header)
        card.add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
        card.add(caption)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(statusRow)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(toggle)
        return card
    }

    private fun currentUrl(): String = "http://${config.host}:${config.port}/mcp"

    private fun statusOf(state: ServerState): UiKit.Status = when (state) {
        ServerState.Running -> UiKit.Status.RUNNING
        ServerState.Failed -> UiKit.Status.FAILED
        ServerState.Starting, ServerState.Stopping -> UiKit.Status.PENDING
        ServerState.Stopped -> UiKit.Status.STOPPED
    }
}
