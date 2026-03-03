package burp.mcp.intercept

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpRequestResponse
import burp.api.montoya.http.message.requests.HttpRequest
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import java.awt.*
import java.text.SimpleDateFormat
import java.util.*
import javax.swing.*
import javax.swing.table.AbstractTableModel

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

    private var selectedMessageId: String? = null
    private var isRefreshing = false

    private val store get() = interceptManager.store

    fun cleanup() {
        refreshTimer?.stop()
        refreshTimer = null
    }

    private fun buildUi(): JPanel {
        // --- Top toolbar ---
        val interceptStatusLabel = JLabel("Disabled").apply {
            font = font.deriveFont(Font.BOLD)
            foreground = Color.GRAY
        }
        val interceptCheckbox = JCheckBox("Enable", interceptManager.isEnabled())
        pendingCountLabel = JLabel("Pending: 0")
        val forwardAllButton = JButton("Forward All & Disable")

        fun updateInterceptStatus(enabled: Boolean) {
            interceptStatusLabel.text = if (enabled) "Enabled" else "Disabled"
            interceptStatusLabel.foreground = if (enabled) Color(0x22, 0x8B, 0x22) else Color.GRAY
            interceptCheckbox.isSelected = enabled
            forwardAllButton.isEnabled = enabled
        }
        updateInterceptStatus(interceptManager.isEnabled())

        interceptManager.addStateListener { enabled ->
            SwingUtilities.invokeLater { updateInterceptStatus(enabled) }
        }

        interceptCheckbox.addActionListener {
            if (interceptCheckbox.isSelected) interceptManager.enable() else interceptManager.disable()
        }

        forwardAllButton.addActionListener {
            interceptManager.disable()
            refreshTable()
        }

        val toolbar = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)).apply {
            add(interceptCheckbox)
            add(JLabel("Status:"))
            add(interceptStatusLabel)
            add(JSeparator(SwingConstants.VERTICAL).apply { preferredSize = Dimension(2, 20) })
            add(pendingCountLabel)
            add(JSeparator(SwingConstants.VERTICAL).apply { preferredSize = Dimension(2, 20) })
            add(forwardAllButton)
        }

        // --- Table ---
        tableModel = MessageTableModel()
        table = JTable(tableModel).apply {
            selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            columnModel.getColumn(0).preferredWidth = 60   // #
            columnModel.getColumn(1).preferredWidth = 50   // Type
            columnModel.getColumn(2).preferredWidth = 60   // Method
            columnModel.getColumn(3).preferredWidth = 400  // URL / Summary
            columnModel.getColumn(4).preferredWidth = 120  // Host
            columnModel.getColumn(5).preferredWidth = 80   // Time
        }

        table.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) {
                onSelectionChanged()
            }
        }

        val tableScroll = JScrollPane(table)

        // --- Burp native editors ---
        requestEditor = api.userInterface().createHttpRequestEditor()
        responseEditor = api.userInterface().createHttpResponseEditor()

        cardLayout = CardLayout()
        editorCards = JPanel(cardLayout).apply {
            add(JLabel("Select a message to view", SwingConstants.CENTER), "empty")
            add(requestEditor.uiComponent(), "request")
            add(responseEditor.uiComponent(), "response")
        }
        cardLayout.show(editorCards, "empty")

        // --- Action buttons ---
        forwardButton = JButton("Forward").apply { isEnabled = false }
        forwardEditedButton = JButton("Forward (edited)").apply { isEnabled = false }
        dropButton = JButton("Drop").apply { isEnabled = false }

        forwardButton.addActionListener { performAction(ActionType.FORWARD) }
        forwardEditedButton.addActionListener { performAction(ActionType.FORWARD_EDITED) }
        dropButton.addActionListener { performAction(ActionType.DROP) }

        val buttonPanel = JPanel(FlowLayout(FlowLayout.LEFT, 8, 4)).apply {
            add(forwardButton)
            add(forwardEditedButton)
            add(dropButton)
        }

        val bottomPanel = JPanel(BorderLayout()).apply {
            add(editorCards, BorderLayout.CENTER)
            add(buttonPanel, BorderLayout.SOUTH)
        }

        // --- Split pane ---
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomPanel).apply {
            resizeWeight = 0.3
            dividerLocation = 200
        }

        // --- Refresh timer (1s) ---
        refreshTimer = javax.swing.Timer(1000) {
            refreshTable()
        }.apply { start() }

        // --- Main panel ---
        return JPanel(BorderLayout()).apply {
            add(toolbar, BorderLayout.NORTH)
            add(splitPane, BorderLayout.CENTER)
        }
    }

    private fun refreshTable() {
        val messages = store.pendingMessages()
        val selId = selectedMessageId          // snapshot before model change

        isRefreshing = true
        tableModel.setMessages(messages)
        pendingCountLabel.text = "Pending: ${messages.size}"

        if (selId != null) {
            val row = tableModel.findRowById(selId)
            if (row >= 0) {
                table.selectionModel.setSelectionInterval(row, row)
            } else {
                selectedMessageId = null
                clearEditor()
            }
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
            }
            is PendingResponse -> {
                val httpResponse = HttpResponse.httpResponse(message.rawResponse)
                responseEditor.setResponse(httpResponse)
                cardLayout.show(editorCards, "response")
            }
        }

        setActionButtonsEnabled(true)
    }

    private fun clearEditor() {
        cardLayout.show(editorCards, "empty")
        setActionButtonsEnabled(false)
    }

    private fun setActionButtonsEnabled(enabled: Boolean) {
        forwardButton.isEnabled = enabled
        forwardEditedButton.isEnabled = enabled
        dropButton.isEnabled = enabled
    }

    private enum class ActionType { FORWARD, FORWARD_EDITED, DROP }

    private fun performAction(action: ActionType) {
        val msgId = selectedMessageId ?: return
        val message = store.removeMessage(msgId) ?: return

        when (action) {
            ActionType.FORWARD -> {
                message.future.complete(MessageResolution.Forward())
            }
            ActionType.FORWARD_EDITED -> {
                val modifiedRaw = when (message) {
                    is PendingRequest -> requestEditor.getRequest().toString()
                    is PendingResponse -> responseEditor.getResponse().toString()
                }
                message.future.complete(MessageResolution.Forward(modifiedRaw))
            }
            ActionType.DROP -> {
                message.future.complete(MessageResolution.Drop)
            }
        }

        selectedMessageId = null
        clearEditor()
        refreshTable()
    }

    // --- Table model ---

    private inner class MessageTableModel : AbstractTableModel() {

        private val columns = arrayOf("#", "Type", "Method", "URL / Summary", "Host", "Time")
        private var messages: List<PendingMessage> = emptyList()
        private val timeFormat = SimpleDateFormat("HH:mm:ss")

        fun setMessages(newMessages: List<PendingMessage>) {
            messages = newMessages
            fireTableDataChanged()
        }

        fun getMessageAt(row: Int): PendingMessage? =
            if (row in messages.indices) messages[row] else null

        fun findRowById(id: String): Int =
            messages.indexOfFirst { it.id == id }

        override fun getRowCount(): Int = messages.size
        override fun getColumnCount(): Int = columns.size
        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val msg = messages.getOrNull(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> msg.id
                1 -> if (msg.type == MessageType.REQUEST) "REQ" else "RESP"
                2 -> when (msg) {
                    is PendingRequest -> msg.method
                    is PendingResponse -> msg.initiatingRequestMethod
                }
                3 -> msg.summary
                4 -> when (msg) {
                    is PendingRequest -> "${msg.host}:${msg.port}"
                    is PendingResponse -> ""
                }
                5 -> timeFormat.format(Date(msg.timestamp))
                else -> null
            }
        }
    }
}
