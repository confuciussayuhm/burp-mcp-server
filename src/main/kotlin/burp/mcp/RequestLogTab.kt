package burp.mcp

import burp.api.montoya.MontoyaApi
import burp.api.montoya.http.message.HttpMessage
import burp.api.montoya.http.message.requests.HttpRequest
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
import java.awt.FlowLayout
import java.awt.GridBagConstraints
import java.awt.GridBagLayout
import java.awt.Insets
import java.awt.event.KeyEvent
import java.text.SimpleDateFormat
import java.util.Date
import java.util.regex.Pattern
import javax.swing.BorderFactory
import javax.swing.JCheckBox
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.KeyStroke
import javax.swing.RowFilter
import javax.swing.SwingConstants
import javax.swing.border.EmptyBorder
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer
import javax.swing.table.TableModel
import javax.swing.table.TableRowSorter

/**
 * Logger-style view of the requests issued by the MCP's own send_http* tools.
 *
 * These requests go out via Burp's HTTP API and never touch the proxy or Repeater,
 * so they don't appear in Burp's own Logger/Proxy views. This tab gives the user the
 * same kind of table-over-viewer surface for them: a dense history table on top, the
 * Burp-native request/response editors (read-only) side-by-side below, sortable headers,
 * and a proxy-history-style search across the log.
 */
class RequestLogTab(
    private val api: MontoyaApi,
    private val requestHistory: McpRequestHistory
) {

    val component: Component by lazy { buildUi() }

    private var refreshTimer: javax.swing.Timer? = null
    private var searchDebounce: javax.swing.Timer? = null

    private lateinit var tableModel: LogTableModel
    private lateinit var table: JTable
    private lateinit var sorter: TableRowSorter<TableModel>
    private lateinit var columnFit: UiKit.ColumnFit
    private lateinit var requestEditor: HttpRequestEditor
    private lateinit var responseEditor: HttpResponseEditor
    private lateinit var countLabel: JLabel
    private lateinit var autoScroll: JCheckBox

    private lateinit var searchField: JTextField
    private lateinit var fullMessageBox: JCheckBox
    private lateinit var regexBox: JCheckBox
    private lateinit var caseBox: JCheckBox
    private lateinit var invertBox: JCheckBox

    private var selectedId: Int? = null
    private var isRefreshing = false

    /**
     * Match verdicts for the current search, keyed by record id. Records are immutable once
     * logged, so a verdict only goes stale when the search itself changes — [applyFilter]
     * clears it. Without this the sorter would rescan the whole log on every refresh tick.
     */
    private val matchCache = HashMap<Int, Boolean>()

    fun cleanup() {
        refreshTimer?.stop()
        refreshTimer = null
        searchDebounce?.stop()
        searchDebounce = null
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
            // search row on a third, stretched to whatever width the tab gets
            gbc.gridy = 2; gbc.weightx = 1.0; gbc.fill = GridBagConstraints.HORIZONTAL
            gbc.insets = Insets(UiKit.GAP_NORM, 0, 0, 0)
            toolbar.add(buildSearchRow(), gbc)
        }

        // ── Table ──────────────────────────────────────────────────
        tableModel = LogTableModel()
        table = UiKit.dataTable(tableModel).apply {
            columnModel.getColumn(COL_METHOD).cellRenderer = MethodCellRenderer()
            columnModel.getColumn(COL_STATUS).cellRenderer = StatusCellRenderer()
        }
        // Status and Length render as text but have to sort as numbers.
        sorter = UiKit.installSorter(table, numericColumns = setOf(COL_STATUS, COL_LENGTH))
        columnFit = UiKit.autoFitColumns(table)
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

    // ── Search ─────────────────────────────────────────────────────

    private fun buildSearchRow(): JPanel {
        searchField = JTextField(30).apply {
            font = UiKit.fontBody()
            toolTipText = "Filter the log — matches the table columns and, unless switched off, " +
                "the full request and response text"
            // FlatLaf (Burp's LAF) honours these; other LAFs ignore them harmlessly.
            putClientProperty("JTextField.placeholderText", "Search requests and responses…")
            putClientProperty("JTextField.showClearButton", true)
            document.addDocumentListener(object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent) = scheduleFilter()
                override fun removeUpdate(e: DocumentEvent) = scheduleFilter()
                override fun changedUpdate(e: DocumentEvent) = scheduleFilter()
            })
            registerKeyboardAction(
                { text = "" },
                KeyStroke.getKeyStroke(KeyEvent.VK_ESCAPE, 0),
                JComponent.WHEN_FOCUSED
            )
        }

        fullMessageBox = searchOption("Full message", true, "Also search the raw request and response bytes")
        regexBox = searchOption("Regex", false, "Treat the search term as a regular expression")
        caseBox = searchOption("Case sensitive", false, "Match the search term case-sensitively")
        invertBox = searchOption("Invert", false, "Show only the rows that do NOT match")

        return JPanel(FlowLayout(FlowLayout.LEFT, UiKit.GAP_NORM, 0)).apply {
            isOpaque = false
            add(JLabel("Search:").apply { font = UiKit.fontBody() })
            add(searchField)
            add(fullMessageBox)
            add(regexBox)
            add(caseBox)
            add(invertBox)
        }
    }

    private fun searchOption(label: String, selected: Boolean, tip: String) =
        JCheckBox(label, selected).apply {
            font = UiKit.fontBody()
            toolTipText = tip
            isOpaque = false
            addActionListener { applyFilter() }
        }

    /** Coalesce keystrokes — a full-message scan per character would stutter on a long log. */
    private fun scheduleFilter() {
        searchDebounce?.stop()
        searchDebounce = javax.swing.Timer(SEARCH_DEBOUNCE_MS) { applyFilter() }.apply {
            isRepeats = false
            start()
        }
    }

    private fun applyFilter() {
        val term = searchField.text ?: ""
        matchCache.clear()

        if (term.isEmpty()) {
            markSearchValid(true)
            setRowFilter(null)
            afterViewChanged()
            return
        }

        val pattern = if (regexBox.isSelected) {
            // UNICODE_CASE or the regex path folds only ASCII, while the literal path below
            // folds Unicode — one "Case sensitive" tick would then mean two different things.
            val flags = if (caseBox.isSelected) 0 else Pattern.CASE_INSENSITIVE or Pattern.UNICODE_CASE
            try {
                Pattern.compile(term, flags)
            } catch (_: Exception) {
                // Half-typed pattern: flag the field and leave the current view alone.
                markSearchValid(false)
                return
            }
        } else {
            null
        }

        markSearchValid(true)
        setRowFilter(
            LogRowFilter(
                term = term,
                pattern = pattern,
                caseSensitive = caseBox.isSelected,
                searchFullMessage = fullMessageBox.isSelected,
                invert = invertBox.isSelected
            )
        )
        afterViewChanged()
    }

    /**
     * Installing a filter makes the sorter drop any selection it can no longer show, and it does
     * that synchronously — so without this guard [onSelectionChanged] would read the resulting
     * empty selection as the user deselecting, forget which record was open, blank both editors
     * and re-arm auto-scroll. The guard keeps the selection listener for real clicks only.
     */
    private fun setRowFilter(filter: RowFilter<Any, Any>?) {
        val previous = isRefreshing
        isRefreshing = true
        try {
            sorter.rowFilter = filter
        } finally {
            isRefreshing = previous
        }
    }

    private fun markSearchValid(valid: Boolean) {
        searchField.putClientProperty("JComponent.outline", if (valid) null else "error")
        searchField.repaint()
    }

    /** Filtering changes both the visible row set and the widest text within it. */
    private fun afterViewChanged() {
        columnFit.refresh()
        updateCounts()
    }

    private fun updateCounts() {
        val total = tableModel.rowCount
        val shown = table.rowCount
        countLabel.text = if (shown == total) "Requests: $total" else "Requests: $shown of $total"
    }

    private inner class LogRowFilter(
        private val term: String,
        private val pattern: Pattern?,
        private val caseSensitive: Boolean,
        private val searchFullMessage: Boolean,
        private val invert: Boolean
    ) : RowFilter<Any, Any>() {

        override fun include(entry: Entry<out Any, out Any>): Boolean {
            val modelRow = entry.identifier as? Int ?: return true
            val record = tableModel.getRecordAt(modelRow)
            val hit = if (record != null) {
                matchCache.getOrPut(record.id) { evaluate(entry, record) }
            } else {
                evaluate(entry, null)
            }
            return hit != invert
        }

        private fun evaluate(entry: Entry<out Any, out Any>, record: McpRequestRecord?): Boolean {
            for (i in 0 until entry.valueCount) {
                if (matches(entry.getStringValue(i))) return true
            }
            return searchFullMessage && record != null &&
                (containsTerm(record.request) || containsTerm(record.response))
        }

        /**
         * Montoya searches the message's own bytes, so a multi-megabyte response never has to be
         * turned into a String first — which is what keeps a full-message search over a long log
         * off the EDT's back.
         */
        private fun containsTerm(message: HttpMessage?): Boolean {
            if (message == null) return false
            return try {
                if (pattern != null) message.contains(pattern) else message.contains(term, caseSensitive)
            } catch (_: Exception) {
                false
            }
        }

        private fun matches(hay: String?): Boolean {
            if (hay.isNullOrEmpty()) return false
            return pattern?.matcher(hay)?.find()
                ?: hay.contains(term, ignoreCase = !caseSensitive)
        }
    }

    // ── Refresh ────────────────────────────────────────────────────

    /** Newest-last so auto-scroll to the bottom reveals the most recent request, like Burp's Logger. */
    private fun snapshot(): List<McpRequestRecord> = requestHistory.list().reversed()

    private fun refreshTable() {
        val records = snapshot()
        // Records are immutable once logged, so an unchanged id list means the rows on screen are
        // still correct — rebuilding them would re-serialise the whole log once a second.
        val structurallyEqual = tableModel.hasSameIds(records)

        isRefreshing = true
        if (!structurallyEqual) {
            tableModel.setRecords(records)
            columnFit.refresh()
        }
        updateCounts()

        val selId = selectedId
        if (selId != null) {
            val modelRow = tableModel.findRowById(selId)
            if (modelRow < 0) {
                selectedId = null
                clearEditors()
            } else {
                // -1 when the active search filters the selection out; leave the editors on it.
                val viewRow = table.convertRowIndexToView(modelRow)
                if (viewRow >= 0 && table.selectedRow != viewRow) {
                    table.selectionModel.setSelectionInterval(viewRow, viewRow)
                }
            }
        } else if (autoScroll.isSelected && records.isNotEmpty()) {
            // The newest record is the last *model* row; sorting can put it anywhere in the view.
            val viewRow = table.convertRowIndexToView(records.size - 1)
            if (viewRow >= 0) table.scrollRectToVisible(table.getCellRect(viewRow, 0, true))
        }
        isRefreshing = false
    }

    private fun onSelectionChanged() {
        if (isRefreshing) return
        val viewRow = table.selectedRow
        if (viewRow < 0) {
            selectedId = null
            clearEditors()
            return
        }
        val modelRow = table.convertRowIndexToModel(viewRow)
        val record = tableModel.getRecordAt(modelRow) ?: return
        selectedId = record.id
        try { requestEditor.setRequest(record.request) } catch (_: Exception) {}
        val resp = record.response
        responseEditor.setResponse(resp ?: HttpResponse.httpResponse(""))
    }

    private fun clearEditors() {
        try { requestEditor.setRequest(HttpRequest.httpRequest("")) } catch (_: Exception) {}
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
        val time: UiKit.TimeCell
    )

    private inner class LogTableModel : AbstractTableModel() {
        private val columns = arrayOf("#", "Host", "Method", "URL", "Status", "Length", "MIME", "Time")
        private var records: List<McpRequestRecord> = emptyList()
        private var rows: List<LogRow> = emptyList()
        private val timeFormat = SimpleDateFormat("HH:mm:ss")

        fun setRecords(newRecords: List<McpRequestRecord>) {
            records = newRecords
            rows = newRecords.map { toRow(it) }
            fireTableDataChanged()
        }

        fun hasSameIds(candidate: List<McpRequestRecord>): Boolean {
            if (candidate.size != records.size) return false
            return records.indices.all { records[it].id == candidate[it].id }
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
                time = UiKit.TimeCell(item.timestamp, timeFormat.format(Date(item.timestamp)))
            )
        }

        fun getRecordAt(row: Int): McpRequestRecord? =
            if (row in records.indices) records[row] else null

        fun findRowById(id: Int): Int = records.indexOfFirst { it.id == id }

        override fun getRowCount(): Int = rows.size
        override fun getColumnCount(): Int = columns.size
        override fun getColumnName(column: Int): String = columns[column]

        override fun getColumnClass(columnIndex: Int): Class<*> = when (columnIndex) {
            COL_ID -> Integer::class.javaObjectType
            COL_TIME -> UiKit.TimeCell::class.java
            else -> String::class.java
        }

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val r = rows.getOrNull(rowIndex) ?: return null
            return when (columnIndex) {
                COL_ID -> r.id
                COL_HOST -> r.host
                COL_METHOD -> r.method
                COL_URL -> r.url
                COL_STATUS -> r.status
                COL_LENGTH -> r.length
                COL_MIME -> r.mime
                COL_TIME -> r.time
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
            // Read the code off the cell value: `row` is a view index once sorting is on.
            val code = value?.toString()?.toIntOrNull()
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

    private companion object {
        const val COL_ID = 0
        const val COL_HOST = 1
        const val COL_METHOD = 2
        const val COL_URL = 3
        const val COL_STATUS = 4
        const val COL_LENGTH = 5
        const val COL_MIME = 6
        const val COL_TIME = 7

        const val SEARCH_DEBOUNCE_MS = 200
    }
}
