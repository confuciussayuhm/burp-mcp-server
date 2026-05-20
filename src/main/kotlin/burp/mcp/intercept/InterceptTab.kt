package burp.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import burp.mcp.ui.UiKit
import java.awt.BorderLayout
import java.awt.CardLayout
import java.awt.Color
import java.awt.Component
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JButton
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.SwingUtilities
import javax.swing.border.EmptyBorder
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/**
 * Lean monitoring view of the MCP intercept queue. Single toolbar row,
 * dense table with theme-aware status/method coloring, and the Burp-native
 * request/response editor below.
 */
class InterceptTab(
    private val api: MontoyaApi,
    private val interceptManager: InterceptManager
) {

    val component: Component by lazy { buildUi() }

    private var refreshTimer: javax.swing.Timer? = null

    private lateinit var tableModel: MessageTableModel
    private lateinit var table: JTable
    private lateinit var requestEditor: HttpRequestEditor
    private lateinit var responseEditor: HttpResponseEditor
    private lateinit var editorCards: JPanel
    private lateinit var cardLayout: CardLayout
    private lateinit var forwardButton: JButton
    private lateinit var forwardEditedButton: JButton
    private lateinit var dropButton: JButton
    private lateinit var pendingCountLabel: JLabel
    private lateinit var statusDotHolder: JPanel
    private lateinit var statusText: JLabel
    private lateinit var autoScroll: JCheckBox

    private var selectedMessageId: String? = null
    private var isRefreshing = false
    private var originalRaw: String = ""

    private val store get() = interceptManager.store

    fun cleanup() {
        refreshTimer?.stop()
        refreshTimer = null
    }

    private fun buildUi(): JPanel {
        // ── Toolbar ────────────────────────────────────────────────
        val state = interceptManager.isEnabled()
        statusDotHolder = JPanel(BorderLayout()).apply {
            isOpaque = false
            add(UiKit.statusDot(if (state) UiKit.Status.RUNNING else UiKit.Status.STOPPED, 12), BorderLayout.CENTER)
        }
        statusText = JLabel(if (state) "Enabled" else "Disabled").apply { font = UiKit.fontHeader() }
        val toggle = JCheckBox("Intercept", state).apply { font = UiKit.fontBody() }
        pendingCountLabel = JLabel("Pending: 0").apply { font = UiKit.fontBody() }
        autoScroll = JCheckBox("Auto-scroll", true).apply { font = UiKit.fontBody() }
        val forwardAllButton = JButton("Forward All & Disable").apply { isEnabled = state }

        fun refreshStatus(enabled: Boolean) {
            statusText.text = if (enabled) "Enabled" else "Disabled"
            toggle.isSelected = enabled
            forwardAllButton.isEnabled = enabled
            statusDotHolder.removeAll()
            statusDotHolder.add(
                UiKit.statusDot(if (enabled) UiKit.Status.RUNNING else UiKit.Status.STOPPED, 12),
                BorderLayout.CENTER
            )
            statusDotHolder.revalidate()
            statusDotHolder.repaint()
        }
        interceptManager.addStateListener { enabled ->
            SwingUtilities.invokeLater { refreshStatus(enabled) }
        }
        toggle.addActionListener {
            if (toggle.isSelected) interceptManager.enable() else interceptManager.disable()
        }
        forwardAllButton.addActionListener {
            interceptManager.disable()
            refreshTable()
        }

        val toolbar = JPanel(GridBagLayout()).apply {
            border = EmptyBorder(0, 0, UiKit.GAP_NORM, 0)
        }
        run {
            val gbc = GridBagConstraints().apply {
                insets = Insets(0, 0, 0, UiKit.GAP_NORM)
                anchor = GridBagConstraints.WEST
            }
            gbc.gridx = 0; gbc.gridy = 0
            toolbar.add(statusDotHolder, gbc)
            gbc.gridx = 1
            toolbar.add(statusText, gbc)
            gbc.gridx = 2
            toolbar.add(toggle, gbc)
            gbc.gridx = 3; gbc.insets = Insets(0, UiKit.GAP_WIDE, 0, UiKit.GAP_NORM)
            toolbar.add(pendingCountLabel, gbc)
            gbc.gridx = 4; gbc.insets = Insets(0, 0, 0, UiKit.GAP_NORM)
            toolbar.add(forwardAllButton, gbc)
            gbc.gridx = 5; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
            toolbar.add(JLabel(""), gbc)
            gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE
            gbc.gridx = 6
            toolbar.add(autoScroll, gbc)
        }

        // ── Table ──────────────────────────────────────────────────
        tableModel = MessageTableModel()
        table = JTable(tableModel).apply {
            selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            rowHeight = 22
            columnModel.getColumn(0).preferredWidth = 50   // #
            columnModel.getColumn(1).preferredWidth = 60   // Type
            columnModel.getColumn(2).preferredWidth = 70   // Method
            columnModel.getColumn(3).preferredWidth = 150  // Host
            columnModel.getColumn(4).preferredWidth = 380  // URL / Summary
            columnModel.getColumn(5).preferredWidth = 80   // Time
            columnModel.getColumn(1).cellRenderer = TypeCellRenderer()
            columnModel.getColumn(2).cellRenderer = MethodCellRenderer()
        }
        table.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) onSelectionChanged()
        }
        val tableScroll = JScrollPane(table)

        // ── Burp native editors ────────────────────────────────────
        requestEditor = api.userInterface().createHttpRequestEditor()
        responseEditor = api.userInterface().createHttpResponseEditor()

        cardLayout = CardLayout()
        editorCards = JPanel(cardLayout).apply {
            add(JPanel(), "empty")
            add(requestEditor.uiComponent(), "request")
            add(responseEditor.uiComponent(), "response")
        }
        cardLayout.show(editorCards, "empty")

        // ── Action buttons ─────────────────────────────────────────
        forwardButton = JButton("Forward").apply { isEnabled = false }
        forwardEditedButton = JButton("Forward edited").apply {
            isEnabled = false
            toolTipText = "Send the message as currently edited in the editor"
        }
        dropButton = JButton("Drop").apply { isEnabled = false }

        forwardButton.addActionListener { performAction(ActionType.FORWARD) }
        forwardEditedButton.addActionListener { performAction(ActionType.FORWARD_EDITED) }
        dropButton.addActionListener { performAction(ActionType.DROP) }

        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_NORM, 0)).apply {
            border = EmptyBorder(UiKit.GAP_NORM, 0, 0, 0)
            add(forwardButton)
            add(forwardEditedButton)
            add(dropButton)
        }

        val bottomPanel = JPanel(BorderLayout()).apply {
            add(editorCards, BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }

        // ── Split ──────────────────────────────────────────────────
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomPanel).apply {
            resizeWeight = 0.35
            dividerLocation = 220
            border = BorderFactory.createEmptyBorder()
        }

        // ── Refresh loop ───────────────────────────────────────────
        refreshTimer = javax.swing.Timer(1000) {
            refreshTable()
            updateForwardEditedEnabled()
        }.apply { start() }

        return JPanel(BorderLayout()).apply {
            border = EmptyBorder(
                UiKit.PAD_OUTER.top,
                UiKit.PAD_OUTER.left,
                UiKit.PAD_OUTER.bottom,
                UiKit.PAD_OUTER.right
            )
            add(toolbar, BorderLayout.NORTH)
            add(splitPane, BorderLayout.CENTER)
        }
    }

    private fun refreshTable() {
        val messages = store.pendingMessages()
        val previousIds = tableModel.idList()
        val newIds = messages.map { it.id }
        val structurallyEqual = previousIds == newIds

        isRefreshing = true
        tableModel.setMessages(messages, fire = !structurallyEqual)
        pendingCountLabel.text = "Pending: ${messages.size}"

        val selId = selectedMessageId
        if (selId != null) {
            val row = tableModel.findRowById(selId)
            if (row >= 0) {
                if (table.selectedRow != row) {
                    table.selectionModel.setSelectionInterval(row, row)
                }
            } else {
                selectedMessageId = null
                clearEditor()
            }
        } else if (autoScroll.isSelected && messages.isNotEmpty()) {
            table.scrollRectToVisible(table.getCellRect(messages.size - 1, 0, true))
        }
        isRefreshing = false
    }

    private fun onSelectionChanged() {
        if (isRefreshing) return
        val row = table.selectedRow
        if (row < 0) {
            selectedMessageId = null
            clearEditor()
            return
        }
        val message = tableModel.getMessageAt(row) ?: return
        selectedMessageId = message.id

        when (message) {
            is PendingRequest -> {
                val httpRequest = HttpRequest.httpRequest(
                    burp.api.montoya.http.HttpService.httpService(message.host, message.port, message.secure),
                    message.rawRequest
                )
                requestEditor.setRequest(httpRequest)
                cardLayout.show(editorCards, "request")
                originalRaw = message.rawRequest
            }
            is PendingResponse -> {
                val httpResponse = HttpResponse.httpResponse(message.rawResponse)
                responseEditor.setResponse(httpResponse)
                cardLayout.show(editorCards, "response")
                originalRaw = message.rawResponse
            }
        }
        forwardButton.isEnabled = true
        forwardEditedButton.isEnabled = false
        dropButton.isEnabled = true
    }

    private fun updateForwardEditedEnabled() {
        if (selectedMessageId == null) return
        val current = currentEditorContent() ?: return
        forwardEditedButton.isEnabled = current != originalRaw
    }

    private fun currentEditorContent(): String? {
        val msgId = selectedMessageId ?: return null
        val msg = store.pendingMessages().firstOrNull { it.id == msgId } ?: return null
        return when (msg) {
            is PendingRequest -> try { requestEditor.getRequest().toString() } catch (_: Exception) { null }
            is PendingResponse -> try { responseEditor.getResponse().toString() } catch (_: Exception) { null }
        }
    }

    private fun clearEditor() {
        cardLayout.show(editorCards, "empty")
        forwardButton.isEnabled = false
        forwardEditedButton.isEnabled = false
        dropButton.isEnabled = false
        originalRaw = ""
    }

    private enum class ActionType { FORWARD, FORWARD_EDITED, DROP }

    private fun performAction(action: ActionType) {
        val msgId = selectedMessageId ?: return
        val message = store.removeMessage(msgId) ?: return
        when (action) {
            ActionType.FORWARD -> message.future.complete(MessageResolution.Forward())
            ActionType.FORWARD_EDITED -> {
                val modifiedRaw = when (message) {
                    is PendingRequest -> requestEditor.getRequest().toString()
                    is PendingResponse -> responseEditor.getResponse().toString()
                }
                message.future.complete(MessageResolution.Forward(modifiedRaw))
            }
            ActionType.DROP -> message.future.complete(MessageResolution.Drop)
        }
        selectedMessageId = null
        clearEditor()
        refreshTable()
    }

    // ── Table model ────────────────────────────────────────────────

    private inner class MessageTableModel : AbstractTableModel() {
        private val columns = arrayOf("#", "Type", "Method", "Host", "URL / Summary", "Time")
        private var messages: List<PendingMessage> = emptyList()
        private val timeFormat = SimpleDateFormat("HH:mm:ss")

        fun setMessages(newMessages: List<PendingMessage>, fire: Boolean) {
            messages = newMessages
            if (fire) fireTableDataChanged()
        }

        fun getMessageAt(row: Int): PendingMessage? =
            if (row in messages.indices) messages[row] else null

        fun findRowById(id: String): Int = messages.indexOfFirst { it.id == id }

        fun idList(): List<String> = messages.map { it.id }

        fun typeOf(row: Int): MessageType? = getMessageAt(row)?.type
        fun methodOf(row: Int): String = when (val m = getMessageAt(row)) {
            is PendingRequest -> m.method
            is PendingResponse -> m.initiatingRequestMethod
            null -> ""
        }

        override fun getRowCount(): Int = messages.size
        override fun getColumnCount(): Int = columns.size
        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val msg = messages.getOrNull(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> msg.id
                1 -> if (msg.type == MessageType.REQUEST) "REQ" else "RES"
                2 -> when (msg) {
                    is PendingRequest -> msg.method
                    is PendingResponse -> msg.initiatingRequestMethod
                }
                3 -> when (msg) {
                    is PendingRequest -> "${msg.host}:${msg.port}"
                    is PendingResponse -> ""
                }
                4 -> msg.summary
                5 -> timeFormat.format(Date(msg.timestamp))
                else -> null
            }
        }
    }

    private inner class TypeCellRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable?,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int
        ): Component {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            val type = tableModel.typeOf(row)
            val (glyph, status) = when (type) {
                MessageType.REQUEST -> "▶ REQ" to UiKit.Status.PENDING
                MessageType.RESPONSE -> "◀ RES" to UiKit.Status.RUNNING
                else -> "—" to UiKit.Status.NEUTRAL
            }
            text = glyph
            if (!isSelected) foreground = UiKit.color(status)
            horizontalAlignment = SwingConstants.LEFT
            return this
        }
    }

    private inner class MethodCellRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable?,
            value: Any?,
            isSelected: Boolean,
            hasFocus: Boolean,
            row: Int,
            column: Int
        ): Component {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            val method = value?.toString() ?: ""
            if (!isSelected) foreground = UiKit.methodColor(method)
            horizontalAlignment = SwingConstants.LEFT
            return this
        }
    }
}
