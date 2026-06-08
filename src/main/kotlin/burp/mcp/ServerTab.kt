package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.mcp.approval.ApprovalKind
import burp.mcp.approval.HistoryResolution
import burp.mcp.approval.PendingApproval
import burp.mcp.approval.PendingApprovalManager
import burp.mcp.intercept.InterceptManager
import burp.mcp.ui.UiKit
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.net.Inet4Address
import java.net.NetworkInterface
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.event.PopupMenuEvent
import javax.swing.event.PopupMenuListener

/**
 * The whole extension UI surface — one tab, four cards: Server, Intercept summary,
 * Security, Approvals. The approvals section is intentionally minimal: Burp's
 * Target Scope is the primary auto-approve source, so this UI focuses on the
 * "everything else" cases (per-host targets, occasional inline approvals,
 * decision history).
 */
class ServerTab(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val server: McpServer,
    private val interceptManager: InterceptManager,
    private val approvals: PendingApprovalManager
) {

    val component: Component by lazy { buildUi() }

    private var pendingCountTimer: javax.swing.Timer? = null

    // Approvals card listeners — held for cleanup.
    private val approvalsListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshApprovalsCard() }
    }
    private val historyListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshApprovalsCard() }
    }
    private val targetsListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshApprovedTargetsList(); refreshApprovalsCard() }
    }
    private var alwaysAllowSyncCallback: (() -> Unit)? = null
    private var autoApproveAllSyncCallback: (() -> Unit)? = null
    private val scopeListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshApprovalsCard() }
    }

    // Approvals UI handles (set in buildApprovalsCard).
    private lateinit var approvalsStatusLabel: JLabel
    private lateinit var pendingHeaderLabel: JLabel
    private lateinit var pendingList: JPanel
    private lateinit var approvedTargetsListModel: DefaultListModel<String>
    private lateinit var approvedTargetsList: JList<String>
    private lateinit var historyListModel: DefaultListModel<String>
    private lateinit var scopeTestField: JTextField
    private lateinit var scopeTestResult: JLabel

    fun cleanup() {
        pendingCountTimer?.stop()
        pendingCountTimer = null
        approvals.removeListener(approvalsListener)
        approvals.history.removeListener(historyListener)
        if (config.onAutoApproveTargetsChanged === targetsListener) {
            config.onAutoApproveTargetsChanged = null
        }
        if (alwaysAllowSyncCallback != null && config.onAlwaysAllowHistoryChanged === alwaysAllowSyncCallback) {
            config.onAlwaysAllowHistoryChanged = null
        }
        if (autoApproveAllSyncCallback != null && config.onAutoApproveAllNewTargetsChanged === autoApproveAllSyncCallback) {
            config.onAutoApproveAllNewTargetsChanged = null
        }
        if (config.onUseBurpScopeChanged === scopeListener) {
            config.onUseBurpScopeChanged = null
        }
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
        val securityCard = buildSecurityCard()
        val approvalsCard = buildApprovalsCard()

        val stack = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            listOf(serverCard, interceptCard, securityCard, approvalsCard).forEachIndexed { i, card ->
                if (i > 0) add(Box.createVerticalStrut(UiKit.GAP_NORM))
                card.alignmentX = JPanel.LEFT_ALIGNMENT
                add(card)
            }
            add(Box.createVerticalGlue())
        }

        val outer = JPanel(BorderLayout()).apply {
            border = EmptyBorder(
                UiKit.PAD_OUTER.top,
                UiKit.PAD_OUTER.left,
                UiKit.PAD_OUTER.bottom,
                UiKit.PAD_OUTER.right
            )
            add(stack, BorderLayout.NORTH)
        }

        val scroll = JScrollPane(outer).apply {
            border = BorderFactory.createEmptyBorder()
            verticalScrollBar.unitIncrement = 16
        }

        approvals.addListener(approvalsListener)
        approvals.history.addListener(historyListener)
        config.onAutoApproveTargetsChanged = targetsListener
        config.onUseBurpScopeChanged = scopeListener
        refreshApprovedTargetsList()
        refreshApprovalsCard()

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
        statusRow.alignmentX = JPanel.LEFT_ALIGNMENT
        formRow.alignmentX = JPanel.LEFT_ALIGNMENT
        copyFeedback.alignmentX = JPanel.LEFT_ALIGNMENT
        portError.alignmentX = JPanel.LEFT_ALIGNMENT
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
        val toggle = JCheckBox("Intercept MCP traffic", state)

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
        statusRow.alignmentX = JPanel.LEFT_ALIGNMENT
        toggle.alignmentX = JPanel.LEFT_ALIGNMENT
        card.add(statusRow)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(toggle)
        return card
    }

    private fun buildSecurityCard(): JPanel {
        val header = UiKit.sectionLabel("Security")

        val configEditing = JCheckBox("Allow tools that can edit your config", config.configEditingTooling)
        val httpApproval = JCheckBox("Require approval for HTTP requests", config.requireHttpRequestApproval)
        val historyApproval = JCheckBox("Require approval for history access", config.requireHistoryAccessApproval)
        val useBurpScope = JCheckBox("Use Burp Target Scope to auto-approve", config.useBurpScopeForApproval).apply {
            toolTipText = "Anything in Burp → Target → Scope is auto-approved without queueing a pending approval."
        }
        val autoApproveAll = JCheckBox(
            "Auto-approve all new targets (capture mode)",
            config.autoApproveAllNewTargets
        ).apply {
            toolTipText = "While on, every new target is auto-approved AND added to the auto-approve list as host:port. " +
                "Use to capture miscellaneous hosts during validation."
        }
        val alwaysHttp = JCheckBox("HTTP history", config.alwaysAllowHttpHistory)
        val alwaysWs = JCheckBox("WebSocket history", config.alwaysAllowWebSocketHistory)

        configEditing.addActionListener { config.configEditingTooling = configEditing.isSelected }
        httpApproval.addActionListener { config.requireHttpRequestApproval = httpApproval.isSelected }
        historyApproval.addActionListener { config.requireHistoryAccessApproval = historyApproval.isSelected }
        useBurpScope.addActionListener { config.useBurpScopeForApproval = useBurpScope.isSelected }
        autoApproveAll.addActionListener { config.autoApproveAllNewTargets = autoApproveAll.isSelected }
        alwaysHttp.addActionListener { config.alwaysAllowHttpHistory = alwaysHttp.isSelected }
        alwaysWs.addActionListener { config.alwaysAllowWebSocketHistory = alwaysWs.isSelected }

        val syncCallback: () -> Unit = {
            SwingUtilities.invokeLater {
                alwaysHttp.isSelected = config.alwaysAllowHttpHistory
                alwaysWs.isSelected = config.alwaysAllowWebSocketHistory
            }
        }
        alwaysAllowSyncCallback = syncCallback
        config.onAlwaysAllowHistoryChanged = syncCallback

        val autoApproveAllSync: () -> Unit = {
            SwingUtilities.invokeLater {
                autoApproveAll.isSelected = config.autoApproveAllNewTargets
            }
        }
        autoApproveAllSyncCallback = autoApproveAllSync
        config.onAutoApproveAllNewTargetsChanged = autoApproveAllSync

        val historyCaption = UiKit.caption("History — always allow (skip approval queue)")
        val historyRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_WIDE, 0)).apply {
            isOpaque = false
            add(alwaysHttp)
            add(alwaysWs)
        }

        val body = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            listOf(configEditing, httpApproval, historyApproval, useBurpScope, autoApproveAll).forEach {
                it.alignmentX = JPanel.LEFT_ALIGNMENT
                add(it)
            }
            add(Box.createVerticalStrut(UiKit.GAP_NORM))
            historyCaption.alignmentX = JPanel.LEFT_ALIGNMENT
            add(historyCaption)
            add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            historyRow.alignmentX = JPanel.LEFT_ALIGNMENT
            add(historyRow)
        }

        val card = UiKit.card()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = EmptyBorder(
            UiKit.PAD_CARD.top, UiKit.PAD_CARD.left, UiKit.PAD_CARD.bottom, UiKit.PAD_CARD.right
        )
        header.alignmentX = JPanel.LEFT_ALIGNMENT
        body.alignmentX = JPanel.LEFT_ALIGNMENT
        card.add(header)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(body)
        return card
    }

    private fun buildApprovalsCard(): JPanel {
        val header = UiKit.sectionLabel("Approvals")
        approvalsStatusLabel = JLabel(" ").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.captionFg()
        }

        pendingHeaderLabel = JLabel(" ").apply { font = UiKit.fontBody().deriveFont(java.awt.Font.BOLD) }
        pendingList = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }

        val targetsDisclosure = UiKit.disclosure(
            "Approved targets",
            buildApprovedTargetsEditor(),
            expanded = false
        )
        val historyDisclosure = UiKit.disclosure(
            "Recent decisions",
            buildHistoryView(),
            expanded = false
        )

        val card = UiKit.card()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = EmptyBorder(
            UiKit.PAD_CARD.top, UiKit.PAD_CARD.left, UiKit.PAD_CARD.bottom, UiKit.PAD_CARD.right
        )
        listOf(
            header, approvalsStatusLabel, pendingHeaderLabel, pendingList, targetsDisclosure, historyDisclosure
        ).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }

        card.add(header)
        card.add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
        card.add(approvalsStatusLabel)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(pendingHeaderLabel)
        card.add(pendingList)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(targetsDisclosure)
        card.add(historyDisclosure)
        return card
    }

    private fun buildApprovedTargetsEditor(): JPanel {
        approvedTargetsListModel = DefaultListModel()
        approvedTargetsList = JList(approvedTargetsListModel).apply {
            selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
            visibleRowCount = 4
            font = UiKit.fontBody()
        }

        val addField = JTextField(18).apply {
            putClientProperty("JTextField.placeholderText", "host or host:port…")
            font = UiKit.fontBody()
        }
        val addButton = JButton("Add").apply {
            toolTipText = "e.g. example.com  ·  example.com:8443  ·  *.internal.corp"
        }
        val removeButton = JButton("Remove")

        addButton.addActionListener {
            val raw = addField.text.trim()
            if (raw.isNotEmpty()) {
                config.addAutoApproveTarget(raw)
                addField.text = ""
            }
        }
        addField.addActionListener { addButton.doClick() }
        removeButton.addActionListener {
            val sel = approvedTargetsList.selectedValuesList
            if (sel.isNotEmpty()) config.removeAutoApproveTargets(sel)
        }

        scopeTestField = JTextField(18).apply {
            putClientProperty("JTextField.placeholderText", "host or URL…")
            font = UiKit.fontBody()
        }
        scopeTestResult = JLabel(" ").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.captionFg()
        }
        val testButton = JButton("Check scope")
        val testHandler = Runnable {
            val raw = scopeTestField.text.trim()
            scopeTestResult.text = checkScopeFor(raw)
        }
        testButton.addActionListener { testHandler.run() }
        scopeTestField.addActionListener { testHandler.run() }

        val addRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_TIGHT, 0)).apply {
            isOpaque = false
            add(addField); add(addButton); add(UiKit.spacer(UiKit.GAP_NORM)); add(removeButton)
        }
        val testRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_TIGHT, 0)).apply {
            isOpaque = false
            add(JLabel("Test scope:").apply { font = UiKit.fontCaption(); foreground = UiKit.captionFg() })
            add(scopeTestField); add(testButton); add(scopeTestResult)
        }

        val listScroll = JScrollPane(approvedTargetsList).apply {
            preferredSize = Dimension(360, 90)
            maximumSize = Dimension(Int.MAX_VALUE, 110)
        }
        val body = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = EmptyBorder(UiKit.GAP_TIGHT, 0, UiKit.GAP_NORM, 0)
            listScroll.alignmentX = JPanel.LEFT_ALIGNMENT
            addRow.alignmentX = JPanel.LEFT_ALIGNMENT
            testRow.alignmentX = JPanel.LEFT_ALIGNMENT
            add(listScroll)
            add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            add(addRow)
            add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            add(testRow)
        }
        return body
    }

    private fun buildHistoryView(): JPanel {
        historyListModel = DefaultListModel()
        val list = JList(historyListModel).apply {
            visibleRowCount = 5
            font = UiKit.fontBody()
            selectionMode = ListSelectionModel.SINGLE_SELECTION
        }
        val scroll = JScrollPane(list).apply {
            preferredSize = Dimension(360, 100)
            maximumSize = Dimension(Int.MAX_VALUE, 120)
        }
        return JPanel(BorderLayout()).apply {
            isOpaque = false
            border = EmptyBorder(UiKit.GAP_TIGHT, 0, UiKit.GAP_NORM, 0)
            add(scroll, BorderLayout.CENTER)
        }
    }

    private fun checkScopeFor(input: String): String {
        if (input.isEmpty()) return "Enter a host or URL"
        val urls = if (input.contains("://")) {
            listOf(input)
        } else {
            val (host, portPart) = if (":" in input) {
                val (h, p) = input.split(":", limit = 2)
                h to p
            } else input to null
            buildList {
                if (portPart != null) {
                    add("https://$host:$portPart/")
                    add("http://$host:$portPart/")
                }
                add("https://$host/")
                add("http://$host/")
            }
        }
        for (url in urls) {
            try {
                if (api.scope().isInScope(url)) return "✓ in scope ($url)"
            } catch (_: Exception) {}
        }
        return "✗ not in Burp scope"
    }

    private fun refreshApprovedTargetsList() {
        if (!this::approvedTargetsListModel.isInitialized) return
        approvedTargetsListModel.clear()
        config.getAutoApproveTargetsList().forEach { approvedTargetsListModel.addElement(it) }
    }

    private fun refreshApprovalsCard() {
        if (!this::approvalsStatusLabel.isInitialized) return
        val scopeOn = config.useBurpScopeForApproval
        val targetCount = config.getAutoApproveTargetsList().size
        approvalsStatusLabel.text =
            "Burp scope: ${if (scopeOn) "enabled" else "disabled"}  ·  $targetCount approved target${if (targetCount == 1) "" else "s"}"

        val pending = approvals.store.list().sortedByDescending { it.timestamp }
        pendingHeaderLabel.text = if (pending.isEmpty()) {
            "No pending approvals"
        } else {
            "⏳ ${pending.size} pending approval${if (pending.size == 1) "" else "s"}"
        }
        rebuildPendingList(pending)

        val historyEntries = approvals.history.list().take(20)
        historyListModel.clear()
        if (historyEntries.isEmpty()) {
            historyListModel.addElement("No recent decisions yet.")
        } else {
            val tf = SimpleDateFormat("HH:mm:ss")
            historyEntries.forEach { entry ->
                val glyph = when (entry.resolution) {
                    HistoryResolution.DENIED, HistoryResolution.CLEARED -> "✗"
                    else -> "✓"
                }
                historyListModel.addElement(
                    "$glyph  ${tf.format(Date(entry.resolvedAt))}  ${formatResolution(entry.resolution)} — ${kindLabel(entry.kind)} ${formatTarget(entry.host, entry.port)}"
                )
            }
        }
    }

    private fun rebuildPendingList(pending: List<PendingApproval>) {
        pendingList.removeAll()
        if (pending.isEmpty()) {
            pendingList.revalidate()
            pendingList.repaint()
            return
        }
        val tf = SimpleDateFormat("HH:mm:ss")
        pending.forEach { approval ->
            val row = buildPendingRow(approval, tf)
            row.alignmentX = JPanel.LEFT_ALIGNMENT
            pendingList.add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            pendingList.add(row)
        }
        pendingList.revalidate()
        pendingList.repaint()
    }

    private fun buildPendingRow(approval: PendingApproval, tf: SimpleDateFormat): JPanel {
        val row = JPanel(GridBagLayout()).apply {
            isOpaque = false
            border = EmptyBorder(UiKit.GAP_TIGHT, 0, UiKit.GAP_TIGHT, 0)
        }
        val dot = UiKit.statusDot(UiKit.Status.PENDING, 10)
        val descLabel = JLabel(
            "${kindLabel(approval.kind)} → ${formatTarget(approval.host, approval.port)}"
        ).apply { font = UiKit.fontBody() }
        val metaLabel = JLabel("${tf.format(Date(approval.timestamp))} · hit ${approval.hitCount}").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.captionFg()
        }

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, UiKit.GAP_TIGHT, 0)).apply { isOpaque = false }
        when (approval.kind) {
            ApprovalKind.HTTP_REQUEST -> {
                if (approval.host != null) {
                    buttons.add(JButton("Approve host").apply {
                        toolTipText = "Add ${approval.host} to approved targets"
                        addActionListener {
                            config.addAutoApproveTarget(approval.host!!)
                            approvals.resolve(approval.id, HistoryResolution.APPROVED_HOST)
                        }
                    })
                }
                if (approval.host != null && approval.port != null) {
                    buttons.add(JButton("Approve host:port").apply {
                        toolTipText = "Add ${approval.host}:${approval.port} to approved targets"
                        addActionListener {
                            config.addAutoApproveTarget("${approval.host}:${approval.port}")
                            approvals.resolve(approval.id, HistoryResolution.APPROVED_HOST_PORT)
                        }
                    })
                }
            }
            ApprovalKind.HTTP_HISTORY, ApprovalKind.WEBSOCKET_HISTORY -> {
                buttons.add(JButton("Always allow").apply {
                    toolTipText = "Always allow this history type"
                    addActionListener {
                        when (approval.kind) {
                            ApprovalKind.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                            ApprovalKind.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                            else -> {}
                        }
                        approvals.resolve(approval.id, HistoryResolution.APPROVED_ALWAYS)
                    }
                })
            }
        }
        buttons.add(JButton("Deny").apply {
            addActionListener { approvals.resolve(approval.id, HistoryResolution.DENIED) }
        })

        val gbc = GridBagConstraints().apply {
            insets = Insets(0, 0, 0, UiKit.GAP_NORM)
            anchor = GridBagConstraints.WEST
        }
        gbc.gridx = 0; gbc.gridy = 0
        row.add(dot, gbc)
        gbc.gridx = 1
        row.add(descLabel, gbc)
        gbc.gridx = 2; gbc.insets = Insets(0, UiKit.GAP_NORM, 0, UiKit.GAP_NORM)
        row.add(metaLabel, gbc)
        gbc.gridx = 3; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
        row.add(JLabel(""), gbc)
        gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE
        gbc.gridx = 4
        row.add(buttons, gbc)
        return row
    }

    private fun formatTarget(host: String?, port: Int?): String = when {
        host != null && port != null -> "$host:$port"
        host != null -> host
        else -> "(unknown)"
    }

    private fun kindLabel(kind: ApprovalKind): String = when (kind) {
        ApprovalKind.HTTP_REQUEST -> "HTTP request"
        ApprovalKind.HTTP_HISTORY -> "HTTP history"
        ApprovalKind.WEBSOCKET_HISTORY -> "WebSocket history"
    }

    private fun formatResolution(resolution: HistoryResolution): String = when (resolution) {
        HistoryResolution.APPROVED_MANUAL -> "approved"
        HistoryResolution.APPROVED_HOST -> "approved (host)"
        HistoryResolution.APPROVED_HOST_PORT -> "approved (host:port)"
        HistoryResolution.APPROVED_ALWAYS -> "approved (always)"
        HistoryResolution.DENIED -> "denied"
        HistoryResolution.CLEARED -> "cleared"
    }

    private fun currentUrl(): String = "http://${config.host}:${config.port}/mcp"

    private fun statusOf(state: ServerState): UiKit.Status = when (state) {
        ServerState.Running -> UiKit.Status.RUNNING
        ServerState.Failed -> UiKit.Status.FAILED
        ServerState.Starting, ServerState.Stopping -> UiKit.Status.PENDING
        ServerState.Stopped -> UiKit.Status.STOPPED
    }
}
