package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.responses.HttpResponse
import burp.api.montoya.ui.editor.EditorOptions
import burp.api.montoya.ui.editor.HttpRequestEditor
import burp.api.montoya.ui.editor.HttpResponseEditor
import burp.mcp.history.McpRequestHistory
import burp.mcp.history.McpRequestRecord
import burp.mcp.tools.toSerializableForm
import burp.mcp.ui.UiKit
import java.awt.BorderLayout
import java.awt.Component
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.SwingConstants
import javax.swing.border.EmptyBorder
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/**
 * Logger-style view of the requests issued by the MCP's own send_http* tools.
 *
 * These requests go out via Burp's HTTP API and never touch the proxy or Repeater,
 * so they don't appear in Burp's own Logger/Proxy views. This tab gives the user the
 * same kind of table-over-viewer surface for them: a dense history table on top, the
 * Burp-native request/response editors (read-only) side-by-side below.
 */
class RequestLogTab(
    private val api: MontoyaApi,
    private val requestHistory: McpRequestHistory
) {

    val component: Component by lazy { buildUi() }

    private var refreshTimer: javax.swing.Timer? = null

    private lateinit var tableModel: LogTableModel
    private lateinit var table: JTable
    private lateinit var requestEditor: HttpRequestEditor
    private lateinit var responseEditor: HttpResponseEditor
    private lateinit var countLabel: JLabel
    private lateinit var autoScroll: JCheckBox

    private var selectedId: Int? = null
    private var isRefreshing = false

    fun cleanup() {
        refreshTimer?.stop()
        refreshTimer = null
    }

    private fun buildUi(): JPanel {
        // ── Toolbar ────────────────────────────────────────────────
        countLabel = JLabel("Requests: 0").apply { font = UiKit.fontBody() }
        autoScroll = JCheckBox("Auto-scroll", true).apply { font = UiKit.fontBody() }

        val title = JLabel("MCP Request Log").apply { font = UiKit.fontHeader() }
        val subtitle = UiKit.caption("Requests issued by send_http1_request / send_http2_request (not in Proxy or Repeater)")

        val toolbar = JPanel(GridBagLayout()).apply {
            border = EmptyBorder(0, 0, UiKit.GAP_NORM, 0)
        }
        run {
            val gbc = GridBagConstraints().apply {
                insets = Insets(0, 0, 0, UiKit.GAP_NORM)
                anchor = GridBagConstraints.WEST
            }
            gbc.gridx = 0; gbc.gridy = 0
            toolbar.add(title, gbc)
            gbc.gridx = 1; gbc.insets = Insets(0, UiKit.GAP_WIDE, 0, UiKit.GAP_NORM)
            toolbar.add(countLabel, gbc)
            gbc.gridx = 2; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
            toolbar.add(JLabel(""), gbc)
            gbc.weightx = 0.0; gbc.fill = GridBagConstraints.NONE
            gbc.gridx = 3
            toolbar.add(autoScroll, gbc)
            // subtitle on a second row spanning the toolbar
            gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 4
            gbc.insets = Insets(UiKit.GAP_TIGHT, 0, 0, 0)
            toolbar.add(subtitle, gbc)
        }

        // ── Table ──────────────────────────────────────────────────
        tableModel = LogTableModel()
        table = JTable(tableModel).apply {
            selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            rowHeight = 22
            columnModel.getColumn(0).preferredWidth = 45    // #
            columnModel.getColumn(1).preferredWidth = 160   // Host
            columnModel.getColumn(2).preferredWidth = 65    // Method
            columnModel.getColumn(3).preferredWidth = 360   // URL
            columnModel.getColumn(4).preferredWidth = 55    // Status
            columnModel.getColumn(5).preferredWidth = 70    // Length
            columnModel.getColumn(6).preferredWidth = 70    // MIME
            columnModel.getColumn(7).preferredWidth = 75    // Time
            columnModel.getColumn(2).cellRenderer = MethodCellRenderer()
            columnModel.getColumn(4).cellRenderer = StatusCellRenderer()
        }
        table.selectionModel.addListSelectionListener { e ->
            if (!e.valueIsAdjusting) onSelectionChanged()
        }
        val tableScroll = JScrollPane(table)

        // ── Burp native editors (read-only) ────────────────────────
        requestEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY)
        responseEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY)

        val viewerSplit = JSplitPane(
            JSplitPane.HORIZONTAL_SPLIT,
            requestEditor.uiComponent(),
            responseEditor.uiComponent()
        ).apply {
            resizeWeight = 0.5
            border = BorderFactory.createEmptyBorder()
        }

        // ── Split ──────────────────────────────────────────────────
        val splitPane = JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewerSplit).apply {
            resizeWeight = 0.4
            dividerLocation = 240
            border = BorderFactory.createEmptyBorder()
        }

        // ── Refresh loop ───────────────────────────────────────────
        refreshTimer = javax.swing.Timer(1000) {
            refreshTable()
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

    /** Newest-last so auto-scroll to the bottom reveals the most recent request, like Burp's Logger. */
    private fun snapshot(): List<McpRequestRecord> = requestHistory.list().reversed()

    private fun refreshTable() {
        val records = snapshot()
        val previousIds = tableModel.idList()
        val newIds = records.map { it.id }
        val structurallyEqual = previousIds == newIds

        isRefreshing = true
        tableModel.setRecords(records, fire = !structurallyEqual)
        countLabel.text = "Requests: ${records.size}"

        val selId = selectedId
        if (selId != null) {
            val row = tableModel.findRowById(selId)
            if (row >= 0) {
                if (table.selectedRow != row) {
                    table.selectionModel.setSelectionInterval(row, row)
                }
            } else {
                selectedId = null
                clearEditors()
            }
        } else if (autoScroll.isSelected && records.isNotEmpty()) {
            table.scrollRectToVisible(table.getCellRect(records.size - 1, 0, true))
        }
        isRefreshing = false
    }

    private fun onSelectionChanged() {
        if (isRefreshing) return
        val row = table.selectedRow
        if (row < 0) {
            selectedId = null
            clearEditors()
            return
        }
        val record = tableModel.getRecordAt(row) ?: return
        selectedId = record.id
        try { requestEditor.setRequest(record.request) } catch (_: Exception) {}
        val resp = record.response
        responseEditor.setResponse(resp ?: HttpResponse.httpResponse(""))
    }

    private fun clearEditors() {
        try { responseEditor.setResponse(HttpResponse.httpResponse("")) } catch (_: Exception) {}
    }

    // ── Table model ────────────────────────────────────────────────

    private data class LogRow(
        val id: Int,
        val host: String,
        val method: String,
        val url: String,
        val status: String,
        val length: String,
        val mime: String,
        val time: String
    )

    private inner class LogTableModel : AbstractTableModel() {
        private val columns = arrayOf("#", "Host", "Method", "URL", "Status", "Length", "MIME", "Time")
        private var records: List<McpRequestRecord> = emptyList()
        private var rows: List<LogRow> = emptyList()
        private val timeFormat = SimpleDateFormat("HH:mm:ss")

        fun setRecords(newRecords: List<McpRequestRecord>, fire: Boolean) {
            records = newRecords
            rows = newRecords.map { toRow(it) }
            if (fire) fireTableDataChanged()
        }

        private fun toRow(record: McpRequestRecord): LogRow {
            // Reuse the MCP serializer's safe field extraction; bodies/headers excluded for speed.
            val item = record.toSerializableForm(
                includeRequestBody = false, includeResponseBody = false, includeHeaders = false
            )
            val host = when {
                item.host == null -> ""
                item.port != null -> "${item.host}:${item.port}"
                else -> item.host
            }
            return LogRow(
                id = item.id,
                host = host,
                method = item.method ?: "",
                url = item.url ?: "",
                status = item.statusCode?.toString() ?: "",
                length = item.responseLength?.toString() ?: "",
                mime = item.mimeType ?: "",
                time = timeFormat.format(Date(item.timestamp))
            )
        }

        fun getRecordAt(row: Int): McpRequestRecord? =
            if (row in records.indices) records[row] else null

        fun findRowById(id: Int): Int = records.indexOfFirst { it.id == id }

        fun idList(): List<Int> = records.map { it.id }

        fun statusOf(row: Int): String = rows.getOrNull(row)?.status ?: ""

        override fun getRowCount(): Int = rows.size
        override fun getColumnCount(): Int = columns.size
        override fun getColumnName(column: Int): String = columns[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val r = rows.getOrNull(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> r.id
                1 -> r.host
                2 -> r.method
                3 -> r.url
                4 -> r.status
                5 -> r.length
                6 -> r.mime
                7 -> r.time
                else -> null
            }
        }
    }

    private inner class MethodCellRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
        ): Component {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            if (!isSelected) foreground = UiKit.methodColor(value?.toString() ?: "")
            horizontalAlignment = SwingConstants.LEFT
            return this
        }
    }

    private inner class StatusCellRenderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(
            table: JTable?, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int
        ): Component {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            val code = tableModel.statusOf(row).toIntOrNull()
            if (!isSelected) {
                foreground = when (code?.div(100)) {
                    2 -> UiKit.color(UiKit.Status.RUNNING)
                    3 -> UiKit.color(UiKit.Status.NEUTRAL)
                    4 -> UiKit.color(UiKit.Status.PENDING)
                    5 -> UiKit.color(UiKit.Status.FAILED)
                    else -> UiKit.color(UiKit.Status.NEUTRAL)
                }
            }
            horizontalAlignment = SwingConstants.LEFT
            return this
        }
    }
}
