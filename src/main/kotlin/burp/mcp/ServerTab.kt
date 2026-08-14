package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.core.Registration
import burp.mcp.approval.ApprovalKind
import burp.mcp.approval.ApprovalPolicy
import burp.mcp.approval.HistoryEntry
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
import java.util.concurrent.atomic.AtomicBoolean
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JComboBox
import javax.swing.JComponent
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
 * Security, Approvals.
 *
 * Everything that can change an approval outcome funnels through one place. The card used to
 * subscribe to a handful of single-slot config callbacks and nothing else, so it never saw
 * Burp's own Target Scope being edited, never saw traffic that a rule let straight through, and
 * left rows queued for hosts the user had already approved elsewhere. Now: one multicast config
 * listener, a Montoya ScopeChangeHandler, and a coalescing repaint timer so a scan issuing
 * hundreds of approved requests a second cannot flood the EDT.
 */
class ServerTab(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val server: McpServer,
    private val interceptManager: InterceptManager,
    private val approvals: PendingApprovalManager,
    private val policy: ApprovalPolicy
) {

    val component: Component by lazy { onEdt { buildUi() } }

    private var pendingCountTimer: javax.swing.Timer? = null
    private var refreshTimer: javax.swing.Timer? = null
    private var scopeRegistration: Registration? = null
    private var unsubscribeConfig: (() -> Unit)? = null

    // Set by any thread; drained by [refreshTimer] on the EDT. Kept separate because allowed
    // traffic fires the history listener on every single request: folding that into one flag
    // would tear down and rebuild every Approve/Deny button 2.5x a second during a scan.
    private val pendingDirty = AtomicBoolean(true)
    private val activityDirty = AtomicBoolean(true)
    private val settingsDirty = AtomicBoolean(true)

    private val approvalsListener: () -> Unit = { pendingDirty.set(true) }
    private val historyListener: () -> Unit = { activityDirty.set(true) }

    // Root of the scrollable content. Revalidated after a rebuild so a refresh that only
    // changed the status line or the Clear-all button's visibility still re-lays-out the card,
    // not just the pending-row panel.
    private lateinit var contentRoot: JPanel

    // Security card handles.
    private lateinit var securityBoxes: List<Pair<JCheckBox, SecurityRule>>
    private lateinit var bindPostureLabel: JLabel

    // Approvals card handles.
    private lateinit var approvalsStatusLabel: JLabel
    private lateinit var pendingHeaderLabel: JLabel
    private lateinit var pendingList: JPanel
    private lateinit var clearAllButton: JButton
    private lateinit var approvedTargetsListModel: DefaultListModel<String>
    private lateinit var approvedTargetsList: JList<String>
    private lateinit var activityListModel: DefaultListModel<String>
    private lateinit var activityList: JList<String>
    private lateinit var activityHeader: JLabel
    private lateinit var scopeTestField: JTextField
    private lateinit var scopeTestResult: JLabel

    /** One security checkbox: how to read it and how to write it. */
    private class SecurityRule(
        val label: String,
        val tooltip: String?,
        val get: () -> Boolean,
        val set: (Boolean) -> Unit
    )

    fun cleanup() {
        pendingCountTimer?.stop()
        pendingCountTimer = null
        refreshTimer?.stop()
        refreshTimer = null
        scopeRegistration?.let { runCatching { it.deregister() } }
        scopeRegistration = null
        unsubscribeConfig?.invoke()
        unsubscribeConfig = null
        approvals.removeListener(approvalsListener)
        approvals.history.removeListener(historyListener)
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

        contentRoot = JPanel(BorderLayout()).apply {
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

        registerListeners()
        refreshEverything()

        return JPanel(BorderLayout()).apply {
            add(scroll, BorderLayout.CENTER)
        }
    }

    /**
     * Every source that can change what the Approvals card should say.
     *
     * All of them only raise a dirty flag; [refreshTimer] drains it on the EDT. That keeps a
     * burst of auto-approved requests — a scan can produce thousands — from queueing one
     * invokeLater rebuild each and starving the EDT, which is what made the card look frozen.
     */
    private fun registerListeners() {
        approvals.addListener(approvalsListener)
        approvals.history.addListener(historyListener)

        unsubscribeConfig = config.addListener { change ->
            // A rule or the target list changed, so queued approvals may now be moot.
            if (change.isSecurityRule || change == ConfigChange.AUTO_APPROVE_TARGETS) {
                policy.reconcilePending()
            }
            // Only a flag: capture mode fires this once per request, and an invokeLater each
            // time would swamp the EDT during a scan.
            settingsDirty.set(true)
            pendingDirty.set(true)
        }

        // Burp's Target Scope is an auto-approve source, and the user edits it in Burp's own UI
        // where this extension has no other visibility. Without this handler, adding a host to
        // scope left its approval queued here forever.
        scopeRegistration = runCatching {
            api.scope().registerScopeChangeHandler {
                policy.reconcilePending()
                pendingDirty.set(true)
            }
        }.onFailure {
            api.logging().logToError("MCP: could not observe Burp scope changes: ${it.message}")
        }.getOrNull()

        refreshTimer = javax.swing.Timer(400) {
            if (settingsDirty.getAndSet(false)) {
                syncSecurityBoxes()
                refreshBindPosture()
            }
            val pending = pendingDirty.getAndSet(false)
            val activity = activityDirty.getAndSet(false)
            if (pending || activity) refreshApprovalsCard(rebuildPending = pending)
        }.apply { start() }
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

    // --- Security ------------------------------------------------------------------------

    private fun securityRules(): List<SecurityRule> = listOf(
        SecurityRule(
            "Allow tools that can edit your config",
            "Lets MCP call set_project_options / set_user_options.",
            { config.configEditingTooling }, { config.configEditingTooling = it }
        ),
        SecurityRule(
            "Require approval for HTTP requests",
            "Master switch. Off means MCP may reach any host without ever queueing an approval.",
            { config.requireHttpRequestApproval }, { config.requireHttpRequestApproval = it }
        ),
        SecurityRule(
            "Require approval for history access",
            "Master switch for reading proxy / WebSocket / MCP history and stored sessions.",
            { config.requireHistoryAccessApproval }, { config.requireHistoryAccessApproval = it }
        ),
        SecurityRule(
            "Use Burp Target Scope to auto-approve",
            "Anything in Burp → Target → Scope is allowed without queueing an approval.",
            { config.useBurpScopeForApproval }, { config.useBurpScopeForApproval = it }
        ),
        SecurityRule(
            "Auto-approve all new targets (capture mode)",
            "Every new target is allowed AND recorded as host:port in the approved list below, " +
                "so you can see afterwards exactly what was touched.",
            { config.autoApproveAllNewTargets }, { config.autoApproveAllNewTargets = it }
        ),
        SecurityRule(
            "Always allow HTTP history",
            "Skip the approval queue for proxy HTTP history, site map, scanner issues and stored sessions.",
            { config.alwaysAllowHttpHistory }, { config.alwaysAllowHttpHistory = it }
        ),
        SecurityRule(
            "Always allow WebSocket history",
            "Skip the approval queue for proxy WebSocket history.",
            { config.alwaysAllowWebSocketHistory }, { config.alwaysAllowWebSocketHistory = it }
        )
    )

    private fun buildSecurityCard(): JPanel {
        val header = UiKit.sectionLabel("Security")
        bindPostureLabel = JLabel(" ").apply { font = UiKit.fontCaption() }

        securityBoxes = securityRules().map { rule ->
            val box = JCheckBox(rule.label, rule.get()).apply { toolTipText = rule.tooltip }
            box.addActionListener { rule.set(box.isSelected) }
            box to rule
        }

        val restore = JButton("Enable all").apply {
            toolTipText = "Turn every rule above back on — the default for a loopback bind."
            addActionListener { config.enableAllSecurityRules() }
        }

        val body = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            securityBoxes.forEach { (box, _) ->
                box.alignmentX = JPanel.LEFT_ALIGNMENT
                add(box)
            }
            add(Box.createVerticalStrut(UiKit.GAP_NORM))
            val buttonRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_TIGHT, 0)).apply {
                isOpaque = false
                add(restore)
            }
            buttonRow.alignmentX = JPanel.LEFT_ALIGNMENT
            add(buttonRow)
        }

        val card = UiKit.card()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = EmptyBorder(
            UiKit.PAD_CARD.top, UiKit.PAD_CARD.left, UiKit.PAD_CARD.bottom, UiKit.PAD_CARD.right
        )
        listOf(header, bindPostureLabel, body).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }
        card.add(header)
        card.add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
        card.add(bindPostureLabel)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(body)
        return card
    }

    private fun syncSecurityBoxes() {
        if (!this::securityBoxes.isInitialized) return
        securityBoxes.forEach { (box, rule) ->
            val actual = rule.get()
            if (box.isSelected != actual) box.isSelected = actual
        }
    }

    private fun refreshBindPosture() {
        if (!this::bindPostureLabel.isInitialized) return
        // Short label, detail in the tooltip: a non-wrapping JLabel holding a full sentence sets
        // the preferred width of the whole tab and forces a horizontal scrollbar.
        if (config.isLoopbackBind()) {
            bindPostureLabel.text = "${config.host} · loopback"
            bindPostureLabel.toolTipText = "Bound to ${config.host} — reachable only from this machine."
            bindPostureLabel.foreground = UiKit.captionFg()
        } else {
            val relaxed = listOf(
                config.configEditingTooling,
                config.autoApproveAllNewTargets,
                config.alwaysAllowHttpHistory,
                config.alwaysAllowWebSocketHistory,
                !config.requireHttpRequestApproval,
                !config.requireHistoryAccessApproval
            ).count { it }
            bindPostureLabel.text = if (relaxed > 0) {
                "⚠  ${config.host} · network-reachable · $relaxed permissive rule${if (relaxed == 1) "" else "s"}"
            } else {
                "⚠  ${config.host} · network-reachable"
            }
            bindPostureLabel.toolTipText =
                "Bound to ${config.host}, so anyone who can reach this port drives Burp through MCP. " +
                    "Consider binding to 127.0.0.1, or turning the permissive rules off."
            bindPostureLabel.foreground = UiKit.color(UiKit.Status.FAILED)
        }
    }

    // --- Approvals -----------------------------------------------------------------------

    private fun buildApprovalsCard(): JPanel {
        val header = UiKit.sectionLabel("Approvals")
        approvalsStatusLabel = JLabel(" ").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.captionFg()
        }

        pendingHeaderLabel = JLabel(" ").apply { font = UiKit.fontBody().deriveFont(java.awt.Font.BOLD) }
        clearAllButton = JButton("Clear all").apply {
            toolTipText = "Discard every queued approval (recorded as cleared)."
            isVisible = false
            addActionListener { approvals.clearAll() }
        }
        val pendingHeaderRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_NORM, 0)).apply {
            isOpaque = false
            add(pendingHeaderLabel)
            add(clearAllButton)
        }

        pendingList = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }

        val targetsDisclosure = UiKit.disclosure(
            "Approved targets",
            buildApprovedTargetsEditor(),
            expanded = false
        )
        // Expanded by default: this list is the answer to "is anything actually getting through?"
        activityHeader = JLabel(" ").apply { font = UiKit.fontCaption(); foreground = UiKit.captionFg() }
        val activityDisclosure = UiKit.disclosure(
            "Activity — allowed and denied, newest first",
            buildActivityView(),
            expanded = true
        )

        val card = UiKit.card()
        card.layout = BoxLayout(card, BoxLayout.Y_AXIS)
        card.border = EmptyBorder(
            UiKit.PAD_CARD.top, UiKit.PAD_CARD.left, UiKit.PAD_CARD.bottom, UiKit.PAD_CARD.right
        )
        listOf(
            header, approvalsStatusLabel, pendingHeaderRow, pendingList, targetsDisclosure, activityDisclosure
        ).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }

        card.add(header)
        card.add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
        card.add(approvalsStatusLabel)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(pendingHeaderRow)
        card.add(pendingList)
        card.add(Box.createVerticalStrut(UiKit.GAP_NORM))
        card.add(targetsDisclosure)
        card.add(activityDisclosure)
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
        val testButton = JButton("Check")
        val testHandler = Runnable { scopeTestResult.text = explainDecisionFor(scopeTestField.text.trim()) }
        testButton.addActionListener { testHandler.run() }
        scopeTestField.addActionListener { testHandler.run() }

        val addRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_TIGHT, 0)).apply {
            isOpaque = false
            add(addField); add(addButton); add(UiKit.spacer(UiKit.GAP_NORM)); add(removeButton)
        }
        val testRow = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_TIGHT, 0)).apply {
            isOpaque = false
            add(JLabel("Would this be allowed?").apply { font = UiKit.fontCaption(); foreground = UiKit.captionFg() })
            add(scopeTestField); add(testButton); add(scopeTestResult)
        }

        val listScroll = JScrollPane(approvedTargetsList).apply {
            preferredSize = Dimension(360, 90)
            maximumSize = Dimension(Int.MAX_VALUE, 110)
        }
        return JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = EmptyBorder(UiKit.GAP_TIGHT, 0, UiKit.GAP_NORM, 0)
            listOf(listScroll, addRow, testRow).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }
            add(listScroll)
            add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            add(addRow)
            add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            add(testRow)
        }
    }

    private fun buildActivityView(): JPanel {
        activityListModel = DefaultListModel()
        activityList = JList(activityListModel).apply {
            visibleRowCount = 8
            font = UiKit.fontCode()
            selectionMode = ListSelectionModel.SINGLE_SELECTION
        }
        val scroll = JScrollPane(activityList).apply {
            preferredSize = Dimension(520, 150)
            maximumSize = Dimension(Int.MAX_VALUE, 190)
        }
        return JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = EmptyBorder(UiKit.GAP_TIGHT, 0, UiKit.GAP_NORM, 0)
            listOf(scroll, activityHeader).forEach { it.alignmentX = JPanel.LEFT_ALIGNMENT }
            add(scroll)
            add(Box.createVerticalStrut(UiKit.GAP_TIGHT))
            add(activityHeader)
        }
    }

    /** Answers the same question the tools ask, so the UI can never disagree with the gate. */
    private fun explainDecisionFor(input: String): String {
        if (input.isEmpty()) return "Enter a host or URL"
        val (host, port, secure) = parseTarget(input) ?: return "Could not parse that"
        val reason = policy.allowReasonForHttpRequest(host, port, secure)
        return if (reason != null) "✓ allowed — ${allowReasonLabel(reason)}" else "✗ would queue an approval"
    }

    private fun parseTarget(input: String): Triple<String, Int?, Boolean>? = try {
        if (input.contains("://")) {
            val uri = java.net.URI(input)
            val host = uri.host ?: return null
            val secure = uri.scheme.equals("https", ignoreCase = true)
            Triple(host, if (uri.port != -1) uri.port else null, secure)
        } else if (":" in input) {
            val (h, p) = input.split(":", limit = 2)
            val port = p.toIntOrNull()
            Triple(h, port, port != 80)
        } else {
            Triple(input, null, true)
        }
    } catch (_: Exception) {
        null
    }

    private fun refreshEverything() {
        syncSecurityBoxes()
        refreshBindPosture()
        refreshApprovedTargetsList()
        refreshApprovalsCard(rebuildPending = true)
    }

    private fun refreshApprovedTargetsList() {
        if (!this::approvedTargetsListModel.isInitialized) return
        val targets = config.getAutoApproveTargetsList()
        val current = (0 until approvedTargetsListModel.size()).map { approvedTargetsListModel.get(it) }
        if (current == targets) return
        val selected = approvedTargetsList.selectedValuesList.toSet()
        approvedTargetsListModel.clear()
        targets.forEach { approvedTargetsListModel.addElement(it) }
        // Keep the selection so a background capture-mode insert cannot make Remove hit the wrong row.
        val indices = targets.withIndex().filter { it.value in selected }.map { it.index }.toIntArray()
        approvedTargetsList.selectedIndices = indices
    }

    private fun refreshApprovalsCard(rebuildPending: Boolean) {
        if (!this::approvalsStatusLabel.isInitialized) return

        refreshApprovedTargetsList()

        val targetCount = config.getAutoApproveTargetsList().size
        approvalsStatusLabel.text = buildString {
            append(
                when {
                    !config.requireHttpRequestApproval -> "HTTP approval OFF"
                    config.autoApproveAllNewTargets -> "capture mode — every new target auto-approved"
                    else -> "HTTP approval required"
                }
            )
            append("  ·  Burp scope: ${if (config.useBurpScopeForApproval) "on" else "off"}")
            append("  ·  $targetCount approved target${if (targetCount == 1) "" else "s"}")
            append("  ·  history: ")
            append(
                when {
                    !config.requireHistoryAccessApproval -> "approval off"
                    config.alwaysAllowHttpHistory && config.alwaysAllowWebSocketHistory -> "always allowed"
                    config.alwaysAllowHttpHistory -> "HTTP always allowed"
                    config.alwaysAllowWebSocketHistory -> "WebSocket always allowed"
                    else -> "approval required"
                }
            )
        }

        // Sort by firstSeen, not lastSeen: lastSeen changes every time the client retries, which
        // would reshuffle rows under the cursor while the user is reaching for a button.
        val pending = approvals.store.list().sortedByDescending { it.firstSeen }
        pendingHeaderLabel.text = if (pending.isEmpty()) {
            "No pending approvals"
        } else {
            "⏳ ${pending.size} pending approval${if (pending.size == 1) "" else "s"}"
        }
        clearAllButton.isVisible = pending.isNotEmpty()
        if (rebuildPending) rebuildPendingList(pending)
        rebuildActivityList()

        if (this::contentRoot.isInitialized) {
            contentRoot.revalidate()
            contentRoot.repaint()
        }
    }

    private fun rebuildActivityList() {
        val entries = approvals.history.list()
        val tf = SimpleDateFormat("HH:mm:ss")
        val rows = if (entries.isEmpty()) {
            listOf("Nothing yet — MCP traffic will appear here as it is allowed or denied.")
        } else {
            entries.take(60).map { formatActivity(it, tf) }
        }

        // Diff first. A blind clear()+refill drops the user's selection, and this runs on every
        // tick that saw traffic — which is exactly when they are trying to read a row.
        val current = (0 until activityListModel.size()).map { activityListModel.get(it) }
        if (current != rows) {
            val selected = activityList.selectedValue
            activityListModel.clear()
            rows.forEach { activityListModel.addElement(it) }
            rows.indexOf(selected).takeIf { it >= 0 }?.let { activityList.selectedIndex = it }
        }

        val allowed = entries.filter { it.resolution.isAllowed }.sumOf { it.hitCount }
        val denied = entries.count { !it.resolution.isAllowed }
        activityHeader.text = if (entries.isEmpty()) " "
            else "$allowed allowed · $denied denied · ${entries.size} target${if (entries.size == 1) "" else "s"} seen"
    }

    private fun formatActivity(entry: HistoryEntry, tf: SimpleDateFormat): String {
        val glyph = if (entry.resolution.isAllowed) "✓" else "✗"
        val hits = if (entry.hitCount > 1) "  ×${entry.hitCount}" else ""
        return "$glyph  ${tf.format(Date(entry.resolvedAt))}  ${kindLabel(entry.kind)} " +
            "${formatTarget(entry.host, entry.port)}  —  ${formatResolution(entry.resolution)}$hits"
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
            // BoxLayout would otherwise stretch a single row over the card's whole height.
            row.maximumSize = Dimension(Int.MAX_VALUE, row.preferredSize.height)
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
        val metaLabel = JLabel("${tf.format(Date(approval.lastSeen))} · hit ${approval.hitCount}").apply {
            font = UiKit.fontCaption()
            foreground = UiKit.captionFg()
        }

        val buttons = JPanel(FlowLayout(FlowLayout.RIGHT, UiKit.GAP_TIGHT, 0)).apply { isOpaque = false }
        val host = approval.host
        val port = approval.port
        when (approval.kind) {
            ApprovalKind.HTTP_REQUEST -> {
                if (host != null) {
                    // Resolve BEFORE widening the rule: addAutoApproveTarget fires the config
                    // listener, which reconciles this same row away as an auto-allow and would
                    // log the user's deliberate click as "auto — approved target".
                    buttons.add(JButton("Approve host").apply {
                        toolTipText = "Add $host to approved targets (any port)"
                        addActionListener {
                            approvals.resolve(approval.id, HistoryResolution.APPROVED_HOST)
                            config.addAutoApproveTarget(host)
                        }
                    })
                    if (port != null) {
                        buttons.add(JButton("Approve host:port").apply {
                            toolTipText = "Add $host:$port to approved targets"
                            addActionListener {
                                approvals.resolve(approval.id, HistoryResolution.APPROVED_HOST_PORT)
                                config.addAutoApproveTarget("$host:$port")
                            }
                        })
                    }
                }
            }
            ApprovalKind.HTTP_HISTORY, ApprovalKind.WEBSOCKET_HISTORY -> {
                buttons.add(JButton("Always allow").apply {
                    toolTipText = "Always allow this history type"
                    addActionListener {
                        approvals.resolve(approval.id, HistoryResolution.APPROVED_ALWAYS)
                        when (approval.kind) {
                            ApprovalKind.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                            ApprovalKind.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                            else -> {}
                        }
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
        else -> "—"
    }

    private fun kindLabel(kind: ApprovalKind): String = when (kind) {
        ApprovalKind.HTTP_REQUEST -> "HTTP request"
        ApprovalKind.HTTP_HISTORY -> "HTTP history"
        ApprovalKind.WEBSOCKET_HISTORY -> "WebSocket history"
    }

    private fun allowReasonLabel(reason: burp.mcp.approval.AllowReason): String = when (reason) {
        burp.mcp.approval.AllowReason.RULE_DISABLED -> "approval not required"
        burp.mcp.approval.AllowReason.APPROVED_TARGET -> "approved target"
        burp.mcp.approval.AllowReason.BURP_SCOPE -> "in Burp scope"
        burp.mcp.approval.AllowReason.CAPTURE_MODE -> "capture mode"
        burp.mcp.approval.AllowReason.ALWAYS_ALLOW -> "always allowed"
    }

    private fun formatResolution(resolution: HistoryResolution): String = when (resolution) {
        HistoryResolution.APPROVED_MANUAL -> "approved"
        HistoryResolution.APPROVED_HOST -> "approved (host)"
        HistoryResolution.APPROVED_HOST_PORT -> "approved (host:port)"
        HistoryResolution.APPROVED_ALWAYS -> "approved (always)"
        HistoryResolution.DENIED -> "denied"
        HistoryResolution.CLEARED -> "cleared"
        HistoryResolution.AUTO_RULE_DISABLED -> "auto — approval not required"
        HistoryResolution.AUTO_TARGET -> "auto — approved target"
        HistoryResolution.AUTO_BURP_SCOPE -> "auto — in Burp scope"
        HistoryResolution.AUTO_CAPTURE -> "auto — capture mode"
        HistoryResolution.AUTO_ALWAYS_ALLOW -> "auto — always allowed"
    }

    private fun currentUrl(): String = "http://${config.host}:${config.port}/mcp"

    private fun statusOf(state: ServerState): UiKit.Status = when (state) {
        ServerState.Running -> UiKit.Status.RUNNING
        ServerState.Failed -> UiKit.Status.FAILED
        ServerState.Starting, ServerState.Stopping -> UiKit.Status.PENDING
        ServerState.Stopped -> UiKit.Status.STOPPED
    }
}
