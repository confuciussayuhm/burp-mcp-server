package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.mcp.intercept.InterceptManager
import java.awt.*
import java.net.Inet4Address
import java.net.NetworkInterface
import javax.swing.*
import javax.swing.event.PopupMenuEvent
import javax.swing.event.PopupMenuListener

class ConfigTab(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val server: McpServer,
    private val interceptManager: InterceptManager
) {

    val component: Component by lazy { buildUi() }

    private var pendingCountTimer: javax.swing.Timer? = null

    fun cleanup() {
        pendingCountTimer?.stop()
        pendingCountTimer = null
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
            // enumeration failed — hardcoded entries suffice
        }
        return entries
    }

    private fun extractIp(display: String): String {
        val space = display.indexOf(' ')
        return if (space > 0) display.substring(0, space) else display
    }

    private fun buildUi(): JTabbedPane {

        // --- Status label (bold, color-coded) ---
        val statusLabel = JLabel(server.state.toString())
        statusLabel.font = statusLabel.font.deriveFont(Font.BOLD)

        fun updateStatusLabel(state: ServerState) {
            statusLabel.text = state.toString()
            statusLabel.foreground = when (state) {
                ServerState.Running -> Color(0x22, 0x8B, 0x22)   // green
                ServerState.Failed -> Color(0xCC, 0x00, 0x00)    // red
                ServerState.Starting, ServerState.Stopping -> Color(0xCC, 0x88, 0x00) // amber
                ServerState.Stopped -> Color.GRAY
            }
        }
        updateStatusLabel(server.state)

        // --- Controls ---
        val enabledCheckbox = JCheckBox("Enable MCP Server", config.enabled)
        val configEditingCheckbox = JCheckBox("Enable tools that can edit your config", config.configEditingTooling)
        val httpApprovalCheckbox = JCheckBox("Require HTTP request approval", config.requireHttpRequestApproval)
        val historyApprovalCheckbox = JCheckBox("Require history access approval", config.requireHistoryAccessApproval)
        val alwaysAllowHttpHistoryCheckbox = JCheckBox("Always allow HTTP history access", config.alwaysAllowHttpHistory)
        val alwaysAllowWsHistoryCheckbox = JCheckBox("Always allow WebSocket history access", config.alwaysAllowWebSocketHistory)

        val hostComboBox = JComboBox<String>().apply {
            isEditable = true
            detectNetworkInterfaces().forEach { addItem(it) }
            // Match current config.host to a display entry, or fall back to raw value
            val match = (0 until itemCount).map { getItemAt(it) }.firstOrNull { extractIp(it) == config.host }
            selectedItem = match ?: config.host
        }

        hostComboBox.addPopupMenuListener(object : PopupMenuListener {
            override fun popupMenuWillBecomeVisible(e: PopupMenuEvent) {
                val current = (hostComboBox.editor.item as? String) ?: (hostComboBox.selectedItem as? String) ?: ""
                hostComboBox.removeAllItems()
                detectNetworkInterfaces().forEach { hostComboBox.addItem(it) }
                val match = (0 until hostComboBox.itemCount).map { hostComboBox.getItemAt(it) }.firstOrNull { extractIp(it) == extractIp(current) }
                hostComboBox.selectedItem = match ?: current
            }
            override fun popupMenuWillBecomeInvisible(e: PopupMenuEvent) {}
            override fun popupMenuCanceled(e: PopupMenuEvent) {}
        })

        val portField = JTextField(config.port.toString(), 6)

        val autoApproveListModel = DefaultListModel<String>().apply {
            config.getAutoApproveTargetsList().forEach { addElement(it) }
        }
        val autoApproveList = JList(autoApproveListModel).apply {
            selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
            visibleRowCount = 5
        }
        val addTargetButton = JButton("Add...")
        val removeTargetButton = JButton("Remove")

        val infoArea = JTextArea().apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
        }

        fun updateInfoText() {
            infoArea.text = "MCP Server for Claude Code integration.\n\n" +
                "To connect: claude mcp add --transport http burp http://${config.host}:${config.port}/mcp\n\n" +
                "The server exposes Burp Suite functionality as MCP tools, including:\n" +
                "- HTTP request sending (HTTP/1.1 and HTTP/2)\n" +
                "- Proxy history browsing\n" +
                "- Repeater/Intruder integration\n" +
                "- Encoding/decoding utilities\n" +
                "- Programmatic request/response interception and modification\n" +
                "- Scanner issue review (Professional edition)\n" +
                "- Collaborator payload generation (Professional edition)\n\n" +
                "To configure via .mcp.json, add:\n\n" +
                "{\n" +
                "  \"mcpServers\": {\n" +
                "    \"burp\": {\n" +
                "      \"type\": \"http\",\n" +
                "      \"url\": \"http://${config.host}:${config.port}/mcp\"\n" +
                "    }\n" +
                "  }\n" +
                "}"
        }

        fun applyConfig(): Boolean {
            val rawSelection = (hostComboBox.editor.item as? String)
                ?: (hostComboBox.selectedItem as? String)
                ?: "127.0.0.1"
            val newHost = extractIp(rawSelection)
            val newPort = portField.text.trim().toIntOrNull()
            if (newPort == null || newPort !in 1..65535) {
                JOptionPane.showMessageDialog(null, "Port must be 1-65535", "Invalid Port", JOptionPane.ERROR_MESSAGE)
                return false
            }
            config.host = newHost
            config.port = newPort
            updateInfoText()
            return true
        }

        updateInfoText()

        server.stateListener = { state ->
            SwingUtilities.invokeLater { updateStatusLabel(state) }
        }

        enabledCheckbox.addActionListener {
            config.enabled = enabledCheckbox.isSelected
            if (config.enabled) {
                if (!applyConfig()) {
                    config.enabled = false
                    enabledCheckbox.isSelected = false
                    return@addActionListener
                }
                server.start()
            } else {
                server.stop()
            }
        }

        fun applyAndRestartIfNeeded() {
            if (!applyConfig()) return
            if (config.enabled) {
                server.stop()
                server.start()
            }
        }

        hostComboBox.addActionListener { applyAndRestartIfNeeded() }

        portField.addFocusListener(object : java.awt.event.FocusAdapter() {
            override fun focusLost(e: java.awt.event.FocusEvent?) {
                applyAndRestartIfNeeded()
            }
        })
        portField.addActionListener { applyAndRestartIfNeeded() }

        configEditingCheckbox.addActionListener { config.configEditingTooling = configEditingCheckbox.isSelected }
        httpApprovalCheckbox.addActionListener { config.requireHttpRequestApproval = httpApprovalCheckbox.isSelected }
        historyApprovalCheckbox.addActionListener { config.requireHistoryAccessApproval = historyApprovalCheckbox.isSelected }
        alwaysAllowHttpHistoryCheckbox.addActionListener { config.alwaysAllowHttpHistory = alwaysAllowHttpHistoryCheckbox.isSelected }
        alwaysAllowWsHistoryCheckbox.addActionListener { config.alwaysAllowWebSocketHistory = alwaysAllowWsHistoryCheckbox.isSelected }

        config.onAutoApproveTargetsChanged = {
            SwingUtilities.invokeLater {
                autoApproveListModel.clear()
                config.getAutoApproveTargetsList().forEach { autoApproveListModel.addElement(it) }
            }
        }

        config.onAlwaysAllowHistoryChanged = {
            SwingUtilities.invokeLater {
                alwaysAllowHttpHistoryCheckbox.isSelected = config.alwaysAllowHttpHistory
                alwaysAllowWsHistoryCheckbox.isSelected = config.alwaysAllowWebSocketHistory
            }
        }

        addTargetButton.addActionListener {
            val input = JOptionPane.showInputDialog(
                null,
                "Enter host to auto-approve (e.g. example.com, *.internal.corp):",
                "Add Auto-approve Target",
                JOptionPane.PLAIN_MESSAGE
            )
            if (input != null && input.trim().isNotEmpty()) {
                config.addAutoApproveTarget(input.trim())
            }
        }

        removeTargetButton.addActionListener {
            val selected = autoApproveList.selectedValuesList
            if (selected.isNotEmpty()) {
                config.removeAutoApproveTargets(selected)
            }
        }

        // ============================
        // Server group
        // ============================
        val serverGroup = JPanel(GridBagLayout()).apply {
            border = BorderFactory.createTitledBorder("Server")
        }
        var gbc = GridBagConstraints().apply {
            insets = Insets(4, 8, 4, 8)
            anchor = GridBagConstraints.WEST
        }

        // Row 0: Status
        gbc.gridx = 0; gbc.gridy = 0; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        serverGroup.add(JLabel("Status:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        serverGroup.add(statusLabel, gbc)

        // Row 1: Enable checkbox (spans 2 columns)
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        serverGroup.add(enabledCheckbox, gbc)
        gbc.gridwidth = 1

        // Row 2: Host
        gbc.gridx = 0; gbc.gridy = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        serverGroup.add(JLabel("Host:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0
        serverGroup.add(hostComboBox, gbc)

        // Row 3: Port
        gbc.gridx = 0; gbc.gridy = 3; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        serverGroup.add(JLabel("Port:"), gbc)
        gbc.gridx = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 1.0
        serverGroup.add(portField, gbc)

        // ============================
        // MCP Interception group
        // ============================
        val interceptStatusLabel = JLabel("Disabled").apply {
            font = font.deriveFont(Font.BOLD)
            foreground = Color.GRAY
        }
        val interceptCheckbox = JCheckBox("Enable MCP Intercept", interceptManager.isEnabled())
        val pendingCountLabel = JLabel("Pending: 0")
        val forwardAllButton = JButton("Forward All & Disable")

        fun updateInterceptUi(enabled: Boolean) {
            interceptStatusLabel.text = if (enabled) "Enabled" else "Disabled"
            interceptStatusLabel.foreground = if (enabled) Color(0x22, 0x8B, 0x22) else Color.GRAY
            interceptCheckbox.isSelected = enabled
            forwardAllButton.isEnabled = enabled
        }
        updateInterceptUi(interceptManager.isEnabled())

        interceptManager.addStateListener { enabled ->
            SwingUtilities.invokeLater { updateInterceptUi(enabled) }
        }

        interceptCheckbox.addActionListener {
            if (interceptCheckbox.isSelected) interceptManager.enable() else interceptManager.disable()
        }

        forwardAllButton.addActionListener {
            interceptManager.disable()
        }

        pendingCountTimer = javax.swing.Timer(1000) {
            pendingCountLabel.text = "Pending: ${interceptManager.store.size()}"
        }.apply { start() }

        val interceptGroup = JPanel(GridBagLayout()).apply {
            border = BorderFactory.createTitledBorder("MCP Interception")
        }
        var igbc = GridBagConstraints().apply {
            insets = Insets(4, 8, 4, 8)
            anchor = GridBagConstraints.WEST
        }

        // Row 0: Status
        igbc.gridx = 0; igbc.gridy = 0; igbc.fill = GridBagConstraints.NONE; igbc.weightx = 0.0
        interceptGroup.add(JLabel("Status:"), igbc)
        igbc.gridx = 1; igbc.fill = GridBagConstraints.HORIZONTAL; igbc.weightx = 1.0
        interceptGroup.add(interceptStatusLabel, igbc)

        // Row 1: Enable checkbox (spans 2 columns)
        igbc.gridx = 0; igbc.gridy = 1; igbc.gridwidth = 2; igbc.fill = GridBagConstraints.NONE; igbc.weightx = 0.0
        interceptGroup.add(interceptCheckbox, igbc)
        igbc.gridwidth = 1

        // Row 2: Pending count
        igbc.gridx = 0; igbc.gridy = 2; igbc.fill = GridBagConstraints.NONE; igbc.weightx = 0.0
        interceptGroup.add(JLabel("Messages:"), igbc)
        igbc.gridx = 1; igbc.fill = GridBagConstraints.HORIZONTAL; igbc.weightx = 1.0
        interceptGroup.add(pendingCountLabel, igbc)

        // Row 3: Forward All button
        igbc.gridx = 1; igbc.gridy = 3; igbc.fill = GridBagConstraints.NONE; igbc.weightx = 0.0
        interceptGroup.add(forwardAllButton, igbc)

        // ============================
        // Security group
        // ============================
        val securityGroup = JPanel(GridBagLayout()).apply {
            border = BorderFactory.createTitledBorder("Security")
        }
        gbc = GridBagConstraints().apply {
            insets = Insets(4, 8, 4, 8)
            anchor = GridBagConstraints.WEST
        }

        var secRow = 0

        // Checkboxes (span 2 columns)
        gbc.gridx = 0; gbc.gridy = secRow; gbc.gridwidth = 2; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0
        securityGroup.add(configEditingCheckbox, gbc)
        gbc.gridy = ++secRow
        securityGroup.add(httpApprovalCheckbox, gbc)
        gbc.gridy = ++secRow
        securityGroup.add(historyApprovalCheckbox, gbc)

        // Sub-heading: History Access Approvals
        gbc.gridy = ++secRow; gbc.insets = Insets(12, 8, 2, 8)
        securityGroup.add(JLabel("History Access Approvals:").apply {
            font = font.deriveFont(Font.BOLD)
        }, gbc)
        gbc.insets = Insets(4, 8, 4, 8)

        gbc.gridy = ++secRow
        securityGroup.add(alwaysAllowHttpHistoryCheckbox, gbc)
        gbc.gridy = ++secRow
        securityGroup.add(alwaysAllowWsHistoryCheckbox, gbc)

        // Sub-heading: Auto-approved Targets
        gbc.gridy = ++secRow; gbc.insets = Insets(12, 8, 2, 8)
        securityGroup.add(JLabel("Auto-approved Targets:").apply {
            font = font.deriveFont(Font.BOLD)
        }, gbc)
        gbc.insets = Insets(4, 8, 4, 8)
        gbc.gridwidth = 1

        // List + buttons
        gbc.gridx = 0; gbc.gridy = ++secRow; gbc.gridwidth = 1
        gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 1.0
        securityGroup.add(JScrollPane(autoApproveList).apply {
            preferredSize = Dimension(300, 100)
        }, gbc)

        val buttonPanel = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(addTargetButton)
            add(Box.createVerticalStrut(4))
            add(removeTargetButton)
        }
        gbc.gridx = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0; gbc.weighty = 0.0
        gbc.anchor = GridBagConstraints.NORTHWEST
        securityGroup.add(buttonPanel, gbc)

        // ============================
        // Assembly
        // ============================
        val settingsPanel = JPanel(BorderLayout(10, 10)).apply {
            border = BorderFactory.createEmptyBorder(15, 15, 15, 15)
            val topPanel = JPanel().apply {
                layout = BoxLayout(this, BoxLayout.Y_AXIS)
                add(serverGroup)
                add(Box.createVerticalStrut(6))
                add(interceptGroup)
                add(Box.createVerticalStrut(6))
                add(securityGroup)
            }
            add(topPanel, BorderLayout.NORTH)
        }

        val setupPanel = JPanel(BorderLayout(10, 10)).apply {
            border = BorderFactory.createEmptyBorder(15, 15, 15, 15)
            val infoScroll = JScrollPane(infoArea).apply {
                border = BorderFactory.createTitledBorder("Connection Info")
            }
            add(infoScroll, BorderLayout.CENTER)
        }

        return JTabbedPane().apply {
            addTab("Settings", settingsPanel)
            addTab("Setup", setupPanel)
        }
    }
}
