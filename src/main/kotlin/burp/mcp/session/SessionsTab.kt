package burp.mcp.session

import burp.mcp.ui.UiKit
import java.awt.BorderLayout
import java.awt.Component
import java.text.SimpleDateFormat
import java.util.Date
import javax.swing.BorderFactory
import javax.swing.JLabel
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JSplitPane
import javax.swing.JTable
import javax.swing.JTextArea
import javax.swing.ListSelectionModel
import javax.swing.border.EmptyBorder
import javax.swing.table.AbstractTableModel

/**
 * Read-only view of the per-role sessions captured this Burp session via the `session_capture` MCP
 * tool. Table on top (role / host / when / cookie preview / auth / extra headers), full material for
 * the selected row below. Refreshes on a timer straight from [SessionStore] (persisted in the Burp
 * project file — banked roles survive restarts).
 *
 * Purely an operator-visibility surface — "what creds does the AI have banked right now" — so a
 * human can see, at a glance, which principals are live for replay-as-role testing.
 */
class SessionsTab(private val store: SessionStore) {

    val component: Component by lazy { buildUi() }

    private var refreshTimer: javax.swing.Timer? = null
    private lateinit var model: SessionTableModel
    private lateinit var table: JTable
    private lateinit var detail: JTextArea
    private lateinit var countLabel: JLabel

    fun cleanup() {
        refreshTimer?.stop()
        refreshTimer = null
    }

    private fun buildUi(): JPanel {
        val title = JLabel("Captured Sessions").apply { font = UiKit.fontHeader() }
        countLabel = JLabel("0 roles").apply { font = UiKit.fontBody() }
        val subtitle = UiKit.caption(
            "Per-role sessions banked via session_capture — used by session_replay_as for concurrent " +
                "multi-principal / IDOR testing. Persisted in the Burp project file; banked roles " +
                "survive Burp restarts."
        )

        val header = JPanel(BorderLayout()).apply {
            border = EmptyBorder(0, 0, UiKit.GAP_NORM, 0)
            val left = JPanel().apply {
                isOpaque = false
                add(title)
                add(countLabel)
            }
            add(left, BorderLayout.WEST)
            add(subtitle, BorderLayout.SOUTH)
        }

        model = SessionTableModel()
        table = JTable(model).apply {
            selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
            autoResizeMode = JTable.AUTO_RESIZE_LAST_COLUMN
            rowHeight = 22
            columnModel.getColumn(0).preferredWidth = 140 // Role
            columnModel.getColumn(1).preferredWidth = 200 // Host
            columnModel.getColumn(2).preferredWidth = 80  // Captured
            columnModel.getColumn(3).preferredWidth = 230 // Cookie
            columnModel.getColumn(4).preferredWidth = 50  // Auth
            columnModel.getColumn(5).preferredWidth = 160 // Extra
        }
        table.selectionModel.addListSelectionListener { e -> if (!e.valueIsAdjusting) showDetail() }

        detail = JTextArea().apply {
            isEditable = false
            lineWrap = true
            wrapStyleWord = false
            font = UiKit.fontCode()
        }

        val split = JSplitPane(JSplitPane.VERTICAL_SPLIT, JScrollPane(table), JScrollPane(detail)).apply {
            resizeWeight = 0.5
            dividerLocation = 220
            border = BorderFactory.createEmptyBorder()
        }

        refreshTimer = javax.swing.Timer(1000) { refresh() }.apply { start() }

        return JPanel(BorderLayout()).apply {
            border = EmptyBorder(
                UiKit.PAD_OUTER.top, UiKit.PAD_OUTER.left, UiKit.PAD_OUTER.bottom, UiKit.PAD_OUTER.right
            )
            add(header, BorderLayout.NORTH)
            add(split, BorderLayout.CENTER)
        }
    }

    private fun refresh() {
        val prevRole = table.selectedRow.takeIf { it >= 0 }?.let { model.roleAt(it) }
        model.setData(store.list())
        val n = model.rowCount()
        countLabel.text = "$n role" + if (n == 1) "" else "s"
        if (prevRole != null) {
            val row = model.rowOfRole(prevRole)
            if (row >= 0 && table.selectedRow != row) {
                table.selectionModel.setSelectionInterval(row, row)
            }
        }
    }

    private fun showDetail() {
        val row = table.selectedRow
        if (row < 0) {
            detail.text = ""
            return
        }
        val s = model.sessionAt(row) ?: return
        detail.text = buildString {
            appendLine("role:     ${s.role}")
            appendLine("host:     ${s.host}")
            appendLine("captured: ${DETAIL_TIME.format(Date(s.capturedAt))}")
            appendLine("sourceId: ${s.sourceId ?: "-"}")
            if (s.note != null) appendLine("note:     ${s.note}")
            appendLine()
            if (s.cookie != null) appendLine("Cookie: ${s.cookie}")
            if (s.authorization != null) appendLine("Authorization: ${s.authorization}")
            s.extraHeaders.forEach { (k, v) -> appendLine("$k: $v") }
        }
        detail.caretPosition = 0
    }

    private class SessionTableModel : AbstractTableModel() {
        private val cols = arrayOf("Role", "Host", "Captured", "Cookie", "Auth", "Extra headers")
        private var rows: List<CapturedSession> = emptyList()
        private val timeFormat = SimpleDateFormat("HH:mm:ss")

        fun rowCount(): Int = rows.size

        fun setData(data: List<CapturedSession>) {
            rows = data
            fireTableDataChanged()
        }

        fun sessionAt(r: Int): CapturedSession? = rows.getOrNull(r)
        fun roleAt(r: Int): String? = rows.getOrNull(r)?.role
        fun rowOfRole(role: String): Int = rows.indexOfFirst { it.role == role }

        override fun getRowCount(): Int = rows.size
        override fun getColumnCount(): Int = cols.size
        override fun getColumnName(column: Int): String = cols[column]

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any? {
            val s = rows.getOrNull(rowIndex) ?: return null
            return when (columnIndex) {
                0 -> s.role
                1 -> s.host
                2 -> timeFormat.format(Date(s.capturedAt))
                3 -> s.cookie?.let { if (it.length <= 32) it else it.take(30) + "…" } ?: "-"
                4 -> if (s.authorization != null) "yes" else "-"
                5 -> s.extraHeaders.keys.joinToString(", ")
                else -> null
            }
        }
    }

    private companion object {
        val DETAIL_TIME = SimpleDateFormat("yyyy-MM-dd HH:mm:ss")
    }
}
