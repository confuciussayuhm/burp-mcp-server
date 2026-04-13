package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.mcp.approval.ApprovalKind
import burp.mcp.approval.PendingApproval
import burp.mcp.approval.PendingApprovalManager
import java.awt.BorderLayout
import java.awt.Component
import java.awt.Dimension
import java.awt.FlowLayout
import java.awt.Font
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JLabel
import javax.swing.JList
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSeparator
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.JTextField
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.table.AbstractTableModel

class ApprovalsTab(
    private val api: MontoyaApi,
    private val config: McpConfig,
    private val approvals: PendingApprovalManager
) {

    val component: Component by lazy { buildUi() }

    private lateinit var tableModel: ApprovalTableModel
    private lateinit var table: JTable
    private lateinit var preview: JTextArea
    private lateinit var pendingCountLabel: JLabel
    private lateinit var approveHostButton: JButton
    private lateinit var approveHostPortButton: JButton
    private lateinit var alwaysAllowButton: JButton
    private lateinit var denyButton: JButton

    private lateinit var autoApproveListModel: DefaultListModel<String>
    private lateinit var autoApproveList: JList<String>
    private lateinit var burpScopeStatusLabel: JLabel
    private lateinit var historyApprovalsLabel: JLabel
    private lateinit var scopeTestField: JTextField
    private lateinit var scopeTestResult: JLabel

    private val approvalsListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshPending() }
    }

    private val targetsListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshAutoApproveList() }
    }

    private val historyListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshHistoryStatus() }
    }

    private val scopeListener: () -> Unit = {
        SwingUtilities.invokeLater { refreshScopeStatus() }
    }

    fun cleanup() {
        approvals.removeListener(approvalsListener)
        if (config.onAutoApproveTargetsChanged === targetsListener) {
            config.onAutoApproveTargetsChanged = null
        }
        if (config.onAlwaysAllowHistoryChanged === historyListener) {
            config.onAlwaysAllowHistoryChanged = null
        }
        if (config.onUseBurpScopeChanged === scopeListener) {
            config.onUseBurpScopeChanged = null
        }
    }

    private fun buildUi(): JPanel {
        val pendingPanel = buildPendingPanel()
        val sourcesPanel = buildSourcesPanel()

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, pendingPanel, sourcesPanel).apply {
            resizeWeight = 0.55
            dividerLocation = 320
        }

        approvals.addListener(approvalsListener)
        config.onAutoApproveTargetsChanged = targetsListener
        config.onAlwaysAllowHistoryChanged = historyListener
        config.onUseBurpScopeChanged = scopeListener
        refreshPending()
        refreshAutoApproveList()
        refreshHistoryStatus()
        refreshScopeStatus()

        return JPanel(BorderLayout()).apply {
            add(split, BorderLayout.CENTER)
        }
    }

    private fun buildPendingPanel(): JPanel {
        pendingCountLabel = JLabel("Pending: 0")
        val clearAllButton = JButton("Clear All")
        clearAllButton.addActionListener { approvals.clearAll() }

        val header = JLabel("Pending Approvals").apply { font = font.deriveFont(Font.BOLD) }

        val toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)).apply {
            add(header)
            add(JSeparator(SwingConstants.VERTICAL).apply { preferredSize = Dimension(2, 20) })
            add(pendingCountLabel)
            add(JSeparator(SwingConstants.VERTICAL).apply { preferredSize = Dimension(2, 20) })
            add(clearAllButton)
        }

        tableModel = ApprovalTableModel()
        table = JTable(tableModel).apply {
            selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            columnModel.getColumn(0).preferredWidth = 60
            columnModel.getColumn(1).preferredWidth = 130
            columnModel.getColumn(2).preferredWidth = 260
            columnModel.getColumn(3).preferredWidth = 100
            columnModel.getColumn(4).preferredWidth = 60
        }
        table.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) onSelectionChanged()
        }

        preview = JTextArea().apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = true
            font = Font(Font.MONOSPACED, Font.PLAIN, 12)
            border = BorderFactory.createEmptyBorder(8, 8, 8, 8)
        }

        approveHostButton = JButton("Approve Host").apply {
            isEnabled = false
            toolTipText = "Add host to Auto-approved Targets (any port)"
        }
        approveHostPortButton = JButton("Approve Host:Port").apply {
            isEnabled = false
            toolTipText = "Add host:port to Auto-approved Targets"
        }
        alwaysAllowButton = JButton("Always Allow").apply {
            isEnabled = false
            toolTipText = "Always allow access to this history type"
        }
        denyButton = JButton("Deny").apply {
            isEnabled = false
            toolTipText = "Remove this pending approval"
        }

        approveHostButton.addActionListener {
            val row = selectedApproval() ?: return@addActionListener
            val host = row.host ?: return@addActionListener
            config.addAutoApproveTarget(host)
            approvals.remove(row.id)
        }
        approveHostPortButton.addActionListener {
            val row = selectedApproval() ?: return@addActionListener
            val host = row.host ?: return@addActionListener
            val port = row.port ?: return@addActionListener
            config.addAutoApproveTarget("$host:$port")
            approvals.remove(row.id)
        }
        alwaysAllowButton.addActionListener {
            val row = selectedApproval() ?: return@addActionListener
            when (row.kind) {
                ApprovalKind.HTTP_HISTORY -> config.alwaysAllowHttpHistory = true
                ApprovalKind.WEBSOCKET_HISTORY -> config.alwaysAllowWebSocketHistory = true
                ApprovalKind.HTTP_REQUEST -> {}
            }
            approvals.remove(row.id)
        }
        denyButton.addActionListener {
            val row = selectedApproval() ?: return@addActionListener
            approvals.remove(row.id)
        }

        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)).apply {
            add(approveHostButton)
            add(approveHostPortButton)
            add(alwaysAllowButton)
            add(denyButton)
        }

        val bottom = JPanel(BorderLayout()).apply {
            add(JScrollPane(preview), BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }

        val innerSplit = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), bottom).apply {
            resizeWeight = 0.5
            dividerLocation = 140
        }

        return JPanel(BorderLayout()).apply {
            add(toolbar, BorderLayout.NORTH)
            add(innerSplit, BorderLayout.CENTER)
        }
    }

    private fun buildSourcesPanel(): JPanel {
        val header = JLabel("Approved Targets — these are auto-approved without queueing").apply {
            font = font.deriveFont(Font.BOLD)
            border = BorderFactory.createEmptyBorder(6, 8, 4, 8)
        }

        autoApproveListModel = DefaultListModel<String>()
        autoApproveList = JList(autoApproveListModel).apply {
            selectionMode = ListSelectionModel.MULTIPLE_INTERVAL_SELECTION
            visibleRowCount = 6
        }

        val addButton = JButton("Add...")
        val removeButton = JButton("Remove")

        addButton.addActionListener {
            val frame = api.userInterface().swingUtils().suiteFrame()
            val input = JOptionPane.showInputDialog(
                frame,
                "Enter host to auto-approve (e.g. example.com, example.com:8443, *.internal.corp):",
                "Add Auto-approve Target",
                JOptionPane.PLAIN_MESSAGE
            )
            if (input != null && input.trim().isNotEmpty()) {
                config.addAutoApproveTarget(input.trim())
            }
        }
        removeButton.addActionListener {
            val selected = autoApproveList.selectedValuesList
            if (selected.isNotEmpty()) config.removeAutoApproveTargets(selected)
        }

        val targetButtons = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            add(addButton)
            add(Box.createVerticalStrut(4))
            add(removeButton)
        }

        val targetsRow = JPanel(GridBagLayout()).apply {
            border = BorderFactory.createEmptyBorder(0, 8, 8, 8)
            val gbc = GridBagConstraints().apply {
                insets = Insets(2, 2, 2, 2)
                anchor = GridBagConstraints.NORTHWEST
            }
            gbc.gridx = 0; gbc.gridy = 0
            gbc.fill = GridBagConstraints.BOTH; gbc.weightx = 1.0; gbc.weighty = 1.0
            add(JScrollPane(autoApproveList).apply { preferredSize = Dimension(360, 120) }, gbc)
            gbc.gridx = 1; gbc.fill = GridBagConstraints.NONE; gbc.weightx = 0.0; gbc.weighty = 0.0
            add(targetButtons, gbc)
        }

        burpScopeStatusLabel = JLabel().apply {
            border = BorderFactory.createEmptyBorder(4, 8, 4, 8)
        }
        historyApprovalsLabel = JLabel().apply {
            border = BorderFactory.createEmptyBorder(0, 8, 4, 8)
        }

        scopeTestField = JTextField(24)
        scopeTestResult = JLabel(" ")
        val testButton = JButton("Check scope")
        val testHandler = Runnable {
            val raw = scopeTestField.text.trim()
            scopeTestResult.text = checkScopeFor(raw)
        }
        testButton.addActionListener { testHandler.run() }
        scopeTestField.addActionListener { testHandler.run() }

        val testRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
            border = BorderFactory.createEmptyBorder(0, 6, 6, 8)
            add(JLabel("Test host:"))
            add(scopeTestField)
            add(testButton)
            add(scopeTestResult)
        }

        val infoSection = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            border = BorderFactory.createTitledBorder("Other auto-approval sources")
            add(burpScopeStatusLabel)
            add(historyApprovalsLabel)
            add(testRow)
        }

        return JPanel(BorderLayout()).apply {
            add(header, BorderLayout.NORTH)
            add(targetsRow, BorderLayout.CENTER)
            add(infoSection, BorderLayout.SOUTH)
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

    private fun selectedApproval(): PendingApproval? {
        val row = table.selectedRow
        if (row < 0) return null
        return tableModel.rowAt(row)
    }

    private fun onSelectionChanged() {
        val row = selectedApproval()
        if (row == null) {
            preview.text = ""
            approveHostButton.isEnabled = false
            approveHostPortButton.isEnabled = false
            alwaysAllowButton.isEnabled = false
            denyButton.isEnabled = false
            return
        }
        preview.text = row.preview
        preview.caretPosition = 0
        when (row.kind) {
            ApprovalKind.HTTP_REQUEST -> {
                approveHostButton.isEnabled = row.host != null
                approveHostPortButton.isEnabled = row.host != null && row.port != null
                alwaysAllowButton.isEnabled = false
            }
            ApprovalKind.HTTP_HISTORY, ApprovalKind.WEBSOCKET_HISTORY -> {
                approveHostButton.isEnabled = false
                approveHostPortButton.isEnabled = false
                alwaysAllowButton.isEnabled = true
            }
        }
        denyButton.isEnabled = true
    }

    private fun refreshPending() {
        val rows = approvals.store.list()
        val selectedId = selectedApproval()?.id
        tableModel.setRows(rows)
        pendingCountLabel.text = "Pending: ${rows.size}"
        if (selectedId != null) {
            val idx = rows.indexOfFirst { it.id == selectedId }
            if (idx >= 0) {
                table.selectionModel.setSelectionInterval(idx, idx)
            } else {
                onSelectionChanged()
            }
        } else {
            onSelectionChanged()
        }
    }

    private fun refreshAutoApproveList() {
        autoApproveListModel.clear()
        config.getAutoApproveTargetsList().forEach { autoApproveListModel.addElement(it) }
    }

    fun refreshScopeStatus() {
        burpScopeStatusLabel.text = if (config.useBurpScopeForApproval) {
            "Burp Target Scope: enabled — anything in Burp → Target → Scope is auto-approved."
        } else {
            "Burp Target Scope: disabled — toggle in MCP → Settings to enable."
        }
    }

    private fun refreshHistoryStatus() {
        val parts = mutableListOf<String>()
        if (config.alwaysAllowHttpHistory) parts.add("HTTP history")
        if (config.alwaysAllowWebSocketHistory) parts.add("WebSocket history")
        historyApprovalsLabel.text = if (parts.isEmpty()) {
            "Always-allow history: none — history access prompts for approval."
        } else {
            "Always-allow history: ${parts.joinToString(", ")}."
        }
    }

    private class ApprovalTableModel : AbstractTableModel() {

        private val columns = arrayOf("#", "Kind", "Host:Port", "First Seen", "Hits")
        private val timeFormat = SimpleDateFormat("HH:mm:ss")
        private var rows: List<PendingApproval> = emptyList()

        fun setRows(newRows: List<PendingApproval>) {
            rows = newRows
            fireTableDataChanged()
        }

        fun rowAt(index: Int): PendingApproval? = rows.getOrNull(index)

        override fun getRowCount(): Int = rows.size
        override fun getColumnCount(): Int = columns.size
        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val row = rows.getOrNull(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> row.id
                1 -> when (row.kind) {
                    ApprovalKind.HTTP_REQUEST -> "HTTP request"
                    ApprovalKind.HTTP_HISTORY -> "HTTP history"
                    ApprovalKind.WEBSOCKET_HISTORY -> "WebSocket history"
                }
                2 -> when {
                    row.host != null && row.port != null -> "${row.host}:${row.port}"
                    row.host != null -> row.host
                    else -> ""
                }
                3 -> timeFormat.format(Date(row.timestamp))
                4 -> row.hitCount
                else -> null
            }
        }
    }
}
