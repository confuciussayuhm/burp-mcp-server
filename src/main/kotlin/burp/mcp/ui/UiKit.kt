package burp.mcp.ui

import java.awt.AlphaComposite
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
import java.awt.EventQueue
import java.awt.FlowLayout
import java.awt.Font
import java.awt.Graphics
import java.awt.Graphics2D
import java.awt.Insets
import java.awt.RenderingHints
import java.awt.datatransfer.StringSelection
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import javax.swing.BorderFactory
import javax.swing.Box
import javax.swing.BoxLayout
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JLabel
import javax.swing.JMenuItem
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.JTable
import javax.swing.ListSelectionModel
import javax.swing.Timer
import javax.swing.UIManager
import javax.swing.border.EmptyBorder
import javax.swing.event.ChangeEvent
import javax.swing.event.ListSelectionEvent
import javax.swing.event.TableColumnModelEvent
import javax.swing.event.TableColumnModelListener
import javax.swing.table.TableCellRenderer
import javax.swing.table.TableModel
import javax.swing.table.TableRowSorter

/**
 * Shared visual language for the MCP extension tabs. Resolves colors against the
 * current LAF, exposes a small spacing scale, and ships factories for the recurring
 * UI primitives (cards, status dots, captions, copy buttons, hyperlinks, disclosures).
 */
object UiKit {

    enum class Status { RUNNING, FAILED, PENDING, STOPPED, NEUTRAL }

    const val GAP_TIGHT = 4
    const val GAP_NORM = 8
    const val GAP_WIDE = 16
    const val GAP_SECTION = 20

    val PAD_CARD: Insets get() = Insets(12, 14, 12, 14)
    val PAD_OUTER: Insets get() = Insets(16, 16, 16, 16)

    fun isDark(): Boolean {
        val bg = UIManager.getColor("Panel.background") ?: Color.WHITE
        val brightness = (bg.red * 299 + bg.green * 587 + bg.blue * 114) / 1000
        return brightness < 128
    }

    fun color(status: Status): Color {
        val dark = isDark()
        return when (status) {
            Status.RUNNING -> if (dark) Color(0x3F, 0xB9, 0x50) else Color(0x22, 0x86, 0x3A)
            Status.FAILED -> if (dark) Color(0xF8, 0x51, 0x49) else Color(0xCF, 0x22, 0x2E)
            Status.PENDING -> if (dark) Color(0xD2, 0x99, 0x22) else Color(0x9A, 0x67, 0x00)
            Status.STOPPED -> UIManager.getColor("Label.disabledForeground")
                ?: (if (dark) Color(0x8B, 0x94, 0x9E) else Color(0x6E, 0x77, 0x81))
            Status.NEUTRAL -> UIManager.getColor("Label.foreground") ?: Color.DARK_GRAY
        }
    }

    fun accent(): Color = UIManager.getColor("Component.focusColor")
        ?: UIManager.getColor("Focus.color")
        ?: (if (isDark()) Color(0x58, 0xA6, 0xFF) else Color(0x05, 0x69, 0xD6))

    fun cardBg(): Color {
        val bg = UIManager.getColor("Panel.background") ?: Color.WHITE
        val shift = if (isDark()) 16 else -8
        return Color(
            clamp(bg.red + shift),
            clamp(bg.green + shift),
            clamp(bg.blue + shift)
        )
    }

    fun cardBorder(): Color {
        val fg = UIManager.getColor("Label.foreground") ?: Color.DARK_GRAY
        val alpha = if (isDark()) 60 else 40
        return Color(fg.red, fg.green, fg.blue, alpha)
    }

    fun captionFg(): Color {
        val fg = UIManager.getColor("Label.foreground") ?: Color.DARK_GRAY
        val alpha = 170
        return Color(fg.red, fg.green, fg.blue, alpha)
    }

    fun fontBody(): Font = UIManager.getFont("Label.font") ?: Font(Font.SANS_SERIF, Font.PLAIN, 12)
    fun fontHeader(): Font = fontBody().deriveFont(Font.BOLD, fontBody().size2D + 2f)
    fun fontCaption(): Font = fontBody().deriveFont(maxOf(10f, fontBody().size2D - 1f))
    fun fontCode(): Font {
        val tf = UIManager.getFont("TextField.font")
        val base = tf?.deriveFont(Font.PLAIN) ?: Font(Font.MONOSPACED, Font.PLAIN, 12)
        return Font(Font.MONOSPACED, Font.PLAIN, base.size)
    }

    fun card(title: String? = null, contentLayout: java.awt.LayoutManager = BorderLayout()): JPanel {
        val card = object : JPanel(contentLayout) {
            init {
                isOpaque = false
                border = EmptyBorder(PAD_CARD.top, PAD_CARD.left, PAD_CARD.bottom, PAD_CARD.right)
            }
            override fun paintComponent(g: Graphics) {
                val g2 = g.create() as Graphics2D
                try {
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                    g2.color = cardBg()
                    g2.fillRoundRect(0, 0, width - 1, height - 1, 10, 10)
                    g2.color = cardBorder()
                    g2.drawRoundRect(0, 0, width - 1, height - 1, 10, 10)
                } finally {
                    g2.dispose()
                }
                super.paintComponent(g)
            }
        }
        if (title != null) {
            val wrap = JPanel(BorderLayout()).apply {
                isOpaque = false
                border = EmptyBorder(0, 0, 0, 0)
            }
            val header = JLabel(title).apply {
                font = fontHeader()
                border = EmptyBorder(0, 0, GAP_NORM, 0)
            }
            wrap.add(header, BorderLayout.NORTH)
            card.add(wrap, BorderLayout.NORTH)
        }
        return card
    }

    fun statusDot(status: Status, diameter: Int = 10): JComponent {
        return object : JComponent() {
            init {
                preferredSize = Dimension(diameter + 2, diameter + 2)
                minimumSize = preferredSize
                maximumSize = preferredSize
                isOpaque = false
            }
            override fun paintComponent(g: Graphics) {
                val g2 = g.create() as Graphics2D
                try {
                    g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON)
                    val c = color(status)
                    g2.color = c
                    val x = (width - diameter) / 2
                    val y = (height - diameter) / 2
                    g2.fillOval(x, y, diameter, diameter)
                    if (status == Status.STOPPED) {
                        g2.composite = AlphaComposite.SrcOver.derive(0.5f)
                        g2.color = c
                        g2.drawOval(x, y, diameter - 1, diameter - 1)
                    }
                } finally {
                    g2.dispose()
                }
            }
        }
    }

    /** Status dot + text label inline, e.g. `[●] Running`. */
    fun statusBadge(status: Status, text: String): JPanel {
        return JPanel(FlowLayout(FlowLayout.LEFT, GAP_TIGHT, 0)).apply {
            isOpaque = false
            border = EmptyBorder(0, 0, 0, 0)
            add(statusDot(status))
            add(JLabel(text).apply { font = fontBody() })
        }
    }

    fun sectionLabel(text: String): JLabel = JLabel(text).apply { font = fontHeader() }

    fun caption(text: String): JLabel = JLabel(text).apply {
        font = fontCaption()
        foreground = captionFg()
    }

    fun link(text: String, onClick: () -> Unit): JLabel {
        val label = JLabel(text)
        label.foreground = accent()
        label.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        label.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) = onClick()
        })
        return label
    }

    /**
     * Toolbar row with consistent inter-component spacing. Mixed in components are
     * separated by `GAP_NORM`; pass `spacer(GAP_WIDE)` between groups for visual breaks.
     */
    fun toolbar(vararg children: Component): JPanel {
        return JPanel(FlowLayout(FlowLayout.LEFT, GAP_NORM, GAP_TIGHT)).apply {
            isOpaque = false
            children.forEach { add(it) }
        }
    }

    fun spacer(width: Int): Component = Box.createHorizontalStrut(width)

    /**
     * Copy button — primary face copies `defaultLabel`'s payload; optional `extra`
     * variants are exposed via a dropdown shown when the chevron is clicked.
     */
    fun copyButton(
        primaryLabel: String,
        primarySupplier: () -> String,
        extras: List<Pair<String, () -> String>> = emptyList(),
        feedback: ((String) -> Unit)? = null
    ): JComponent {
        val container = JPanel(FlowLayout(FlowLayout.LEFT, 0, 0)).apply { isOpaque = false }
        val main = JButton(primaryLabel)
        main.addActionListener {
            copyToClipboard(primarySupplier())
            feedback?.invoke(primaryLabel)
        }
        container.add(main)
        if (extras.isNotEmpty()) {
            val arrow = JButton("▾")
            arrow.toolTipText = "More copy options"
            arrow.addActionListener {
                val menu = JPopupMenu()
                extras.forEach { (label, supplier) ->
                    val item = javax.swing.JMenuItem(label)
                    item.addActionListener {
                        copyToClipboard(supplier())
                        feedback?.invoke(label)
                    }
                    menu.add(item)
                }
                menu.show(arrow, 0, arrow.height)
            }
            container.add(arrow)
        }
        return container
    }

    fun copyToClipboard(text: String) {
        val clipboard = java.awt.Toolkit.getDefaultToolkit().systemClipboard
        clipboard.setContents(StringSelection(text), null)
    }

    /** Transient feedback caption — shows `text` for `millis` ms then clears. */
    fun ephemeral(label: JLabel, text: String, millis: Int = 1500) {
        label.text = text
        val timer = Timer(millis) { label.text = " " }
        timer.isRepeats = false
        timer.start()
    }

    /**
     * Disclosure panel: clickable header that expands/collapses `content`.
     * Returns a `JPanel(BorderLayout)` with header in NORTH and content in CENTER
     * (only visible when expanded).
     */
    fun disclosure(title: String, content: JComponent, expanded: Boolean = false): JPanel {
        val wrap = JPanel(BorderLayout()).apply { isOpaque = false }
        val state = booleanArrayOf(expanded)
        val header = JLabel(formatDisclosure(title, state[0]))
        header.font = fontBody().deriveFont(Font.BOLD)
        header.cursor = Cursor.getPredefinedCursor(Cursor.HAND_CURSOR)
        header.border = EmptyBorder(GAP_TIGHT, 0, GAP_TIGHT, 0)
        content.isVisible = state[0]
        header.addMouseListener(object : MouseAdapter() {
            override fun mouseClicked(e: MouseEvent) {
                state[0] = !state[0]
                header.text = formatDisclosure(title, state[0])
                content.isVisible = state[0]
                // A revalidate() raised inside hidden content is dropped (RepaintManager stops at
                // an invisible ancestor) but its invalidate() half still propagates, so the chain
                // above us is left invalid-but-unscheduled with collapsed geometry cached in the
                // enclosing BoxLayouts. invalidate() short-circuits on an already-invalid
                // component, so walk the chain explicitly or the content expands to height 0.
                var c: java.awt.Container? = wrap
                while (c != null) {
                    c.invalidate()
                    c = c.parent
                }
                wrap.revalidate()
                wrap.repaint()
            }
        })
        wrap.add(header, BorderLayout.NORTH)
        wrap.add(content, BorderLayout.CENTER)
        return wrap
    }

    private fun formatDisclosure(title: String, expanded: Boolean): String {
        val arrow = if (expanded) "▾" else "▸"
        return "$arrow  $title"
    }

    fun verticalStack(vararg children: Component, gap: Int = GAP_NORM): JPanel {
        val panel = JPanel().apply {
            isOpaque = false
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
        }
        children.forEachIndexed { i, c ->
            if (i > 0) panel.add(Box.createVerticalStrut(gap))
            if (c is JComponent) c.alignmentX = JComponent.LEFT_ALIGNMENT
            panel.add(c)
        }
        return panel
    }

    /** HTTP method color, theme-aware. Matches Burp's own convention loosely. */
    fun methodColor(method: String): Color {
        val m = method.uppercase()
        return when (m) {
            "GET" -> color(Status.RUNNING)
            "POST", "PUT", "PATCH" -> color(Status.PENDING)
            "DELETE" -> color(Status.FAILED)
            else -> color(Status.NEUTRAL)
        }
    }

    private fun clamp(v: Int): Int = when {
        v < 0 -> 0
        v > 255 -> 255
        else -> v
    }

    // ── Tables ─────────────────────────────────────────────────────

    /** Floor for an auto-fitted column, so a narrow one never collapses to nothing. */
    private const val COL_MIN = 30

    /** Ceiling on the floor we derive from a header, so a wide header can't jam the layout. */
    private const val COL_MIN_CAP = 120

    /** Breathing room either side of the widest measured cell. */
    private const val CELL_PAD = 12

    /** Rows at the end of the table always measured, so late wide rows still count. */
    private const val TAIL_SAMPLE = 25

    /** Slack a content-sized column may absorb before the stretch column takes the rest. */
    private const val STRETCH_HEADROOM = 80

    /** Width reserved for a sort arrow when the LAF paints one without registering an icon. */
    private const val SORT_ICON_FALLBACK = 16

    /**
     * Renders as formatted text but sorts on the timestamp behind it, so an "HH:mm:ss" column
     * still orders correctly across a log that spans midnight.
     */
    class TimeCell(private val epoch: Long, private val text: String) : Comparable<TimeCell> {
        override fun compareTo(other: TimeCell): Int = epoch.compareTo(other.epoch)
        override fun toString(): String = text
    }

    /**
     * JTable tuned for the dense log-style views in this extension: single selection,
     * compact rows, and a tooltip carrying the full cell text whenever the column is too
     * narrow to show it — which starts to matter once [autoFitColumns] squeezes columns
     * to keep the table inside the window.
     */
    fun dataTable(model: TableModel): JTable {
        val table = object : JTable(model) {
            override fun prepareRenderer(renderer: TableCellRenderer, row: Int, column: Int): Component {
                val c = super.prepareRenderer(renderer, row, column)
                if (c is JComponent) {
                    val text = (c as? JLabel)?.text
                    c.toolTipText = if (!text.isNullOrEmpty() &&
                        c.preferredSize.width > columnModel.getColumn(column).width
                    ) text else null
                }
                return c
            }
        }
        table.selectionModel.selectionMode = ListSelectionModel.SINGLE_SELECTION
        table.rowHeight = 22
        table.fillsViewportHeight = true
        return table
    }

    /** Compares cells that hold numbers rendered as text; blanks sink to the bottom. */
    private val NUMERIC_CELLS: Comparator<Any?> = Comparator { a, b ->
        val x = a?.toString()?.trim()?.toDoubleOrNull()
        val y = b?.toString()?.trim()?.toDoubleOrNull()
        when {
            x != null && y != null -> x.compareTo(y)
            x == null && y == null -> 0
            x == null -> 1
            else -> -1
        }
    }

    /**
     * Click-to-sort headers. Columns named in [numericColumns] hold numbers rendered as text
     * (status codes, byte counts) and get a numeric comparator, so 97 sorts below 404 rather
     * than above it.
     *
     * Once a sorter is installed the table's row indices are *view* indices: every hop to the
     * model has to go through [JTable.convertRowIndexToModel] / [JTable.convertRowIndexToView].
     */
    fun installSorter(table: JTable, numericColumns: Set<Int> = emptySet()): TableRowSorter<TableModel> {
        val sorter = TableRowSorter<TableModel>(table.model)
        sorter.sortsOnUpdates = false
        numericColumns.forEach { sorter.setComparator(it, NUMERIC_CELLS) }
        table.rowSorter = sorter
        return sorter
    }

    /**
     * Sizes each column to the text it actually holds while keeping the whole table inside the
     * viewport: content-derived preferred widths plus `AUTO_RESIZE_SUBSEQUENT_COLUMNS`, which
     * has Swing scale those proportions into whatever width Burp hands the tab. Columns hug
     * their contents, and the row never spills past the window edge or raises a scrollbar.
     *
     * Call [refresh] whenever the model gains rows. Dragging a divider hands sizing over to the
     * user permanently; the header's right-click menu (or [fitNow]) takes it back.
     */
    class ColumnFit internal constructor(
        private val table: JTable,
        private val maxColumnWidth: Int,
        private val sampleCap: Int
    ) {
        private var userAdjusted = false

        /** Widest each column has had to be so far, so live traffic does not make them twitch. */
        private var highWater = IntArray(0)
        private var lastRowCount = -1

        internal fun install() {
            table.autoResizeMode = JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS
            table.columnModel.addColumnModelListener(object : TableColumnModelListener {
                override fun columnMarginChanged(e: ChangeEvent) {
                    if (userAdjusted) return
                    val resizing = table.tableHeader?.resizingColumn ?: return
                    // Under AUTO_RESIZE_SUBSEQUENT_COLUMNS there is nothing after the last column
                    // to take width from, so a drag on its right edge is undone by the next layout.
                    // Latching on it would switch auto-fitting off for a resize that never landed.
                    val columns = table.columnModel
                    if (columns.columnCount > 0 && columns.getColumn(columns.columnCount - 1) === resizing) return
                    // resizingColumn latches on a mouse-press over a divider and stays set until
                    // release, so on its own it cannot tell a real drag from one of our own re-fits
                    // landing mid-press. A user resize is always dispatched from a drag event,
                    // while the refresh timer arrives on an InvocationEvent.
                    val current = EventQueue.getCurrentEvent()
                    if (current !is MouseEvent || current.id != MouseEvent.MOUSE_DRAGGED) return
                    userAdjusted = true
                    // Drop the stretch caps so the drag isn't fenced in by them. Setting the flag
                    // first keeps the events this raises from re-entering.
                    for (i in 0 until table.columnModel.columnCount) {
                        table.columnModel.getColumn(i).maxWidth = Int.MAX_VALUE
                    }
                }

                override fun columnAdded(e: TableColumnModelEvent) {}
                override fun columnRemoved(e: TableColumnModelEvent) {}
                override fun columnMoved(e: TableColumnModelEvent) {}
                override fun columnSelectionChanged(e: ListSelectionEvent) {}
            })
            table.tableHeader?.componentPopupMenu = JPopupMenu().apply {
                add(JMenuItem("Fit columns to contents").apply { addActionListener { fitNow() } })
            }
            refresh()
        }

        /** Re-measure, unless the user has taken the widths over by dragging a divider. */
        fun refresh() {
            if (!userAdjusted) apply()
        }

        /** Re-measure from scratch and take the widths back from a manual drag. */
        fun fitNow() {
            userAdjusted = false
            highWater = IntArray(0)
            lastRowCount = -1
            apply()
        }

        private fun apply() {
            val header = table.tableHeader
            val columns = table.columnModel
            val rowCount = table.rowCount
            val sampled = sampleIndices(rowCount)
            val count = columns.columnCount
            val preferred = IntArray(count)
            val floors = IntArray(count)

            // An empty view says nothing about how wide the content wants to be. Once anything has
            // been measured, hold the layout rather than collapsing to header widths and snapping
            // back the moment rows return — which is what a search matching nothing would otherwise
            // look like. lastRowCount is left alone so the next non-empty view is still compared
            // against the row count these widths came from.
            if (rowCount == 0 && highWater.any { it > 0 }) return

            // Only rows currently in view get measured, and which rows those are shifts as the log
            // grows or a search narrows it. Carrying the widest width seen forward stops the columns
            // twitching on every refresh; a row set that shrank means a fresh start.
            val modelCount = table.model.columnCount
            if (highWater.size != modelCount || rowCount < lastRowCount) highWater = IntArray(modelCount)
            lastRowCount = rowCount

            val sortAllowance = sortIconAllowance()
            for (viewCol in 0 until count) {
                val column = columns.getColumn(viewCol)
                val labelWidth = (column.headerRenderer ?: header?.defaultRenderer)
                    ?.getTableCellRendererComponent(table, column.headerValue, false, false, -1, viewCol)
                    ?.preferredSize?.width ?: 0
                // Room for the sort arrow up front, or clicking a header ellipsises its own label.
                val headerWidth = labelWidth + sortAllowance
                var content = headerWidth
                for (viewRow in sampled) {
                    val renderer = table.getCellRenderer(viewRow, viewCol)
                    content = maxOf(content, table.prepareRenderer(renderer, viewRow, viewCol).preferredSize.width)
                    if (content >= maxColumnWidth) break
                }
                val measured = (content + CELL_PAD).coerceIn(COL_MIN, maxColumnWidth)
                // Keyed by model index, not screen position, so dragging a header to a new place
                // carries its remembered width with it instead of inheriting its neighbour's.
                val modelCol = column.modelIndex
                if (modelCol in 0 until modelCount) {
                    preferred[viewCol] = maxOf(measured, highWater[modelCol])
                    highWater[modelCol] = preferred[viewCol]
                } else {
                    preferred[viewCol] = measured
                }
                // Keep the floor at or below the preferred width — setMinWidth would drag it up.
                floors[viewCol] = minOf(headerWidth + CELL_PAD, preferred[viewCol], COL_MIN_CAP)
                    .coerceAtLeast(COL_MIN)
            }

            // Spare width has to land somewhere. Left to itself JTable spreads it evenly across
            // every column — which blows a 35px "#" column up to 200px in a wide window. Capping
            // each column just above its content and leaving only the wordiest one uncapped sends
            // effectively all of the slack there instead, so the rest keep hugging their text.
            // An empty table has no content to judge by: leave every column uncapped there, or the
            // capped total falls short of the viewport and the table ends in a blank gutter.
            val stretchCol = if (rowCount > 0) (0 until count).maxByOrNull { preferred[it] } ?: -1 else -1
            val capOthers = rowCount > 0

            for (viewCol in 0 until count) {
                val column = columns.getColumn(viewCol)
                column.minWidth = floors[viewCol]
                column.maxWidth = if (viewCol == stretchCol || !capOthers) {
                    Int.MAX_VALUE
                } else {
                    preferred[viewCol] + STRETCH_HEADROOM
                }
                column.preferredWidth = preferred[viewCol]
            }
            table.revalidate()
            table.repaint()
        }

        /** Width a sorted header needs for its arrow, on top of the label itself. */
        private fun sortIconAllowance(): Int {
            if (table.rowSorter == null) return 0
            val icon = maxOf(
                UIManager.getIcon("Table.ascendingSortIcon")?.iconWidth ?: 0,
                UIManager.getIcon("Table.descendingSortIcon")?.iconWidth ?: 0
            )
            // FlatLaf paints the arrow from the header UI without registering an icon, so a zero
            // lookup means "unknown", not "no arrow".
            return if (icon > 0) icon + GAP_TIGHT else SORT_ICON_FALLBACK
        }

        /** Even stride across the table plus its tail, so measuring stays cheap on a long log. */
        private fun sampleIndices(rowCount: Int): List<Int> {
            if (rowCount <= 0) return emptyList()
            if (rowCount <= sampleCap) return (0 until rowCount).toList()
            val stride = (rowCount + sampleCap - 1) / sampleCap
            val rows = (0 until rowCount step stride).toMutableList()
            for (r in maxOf(0, rowCount - TAIL_SAMPLE) until rowCount) rows.add(r)
            return rows.distinct()
        }
    }

    fun autoFitColumns(table: JTable, maxColumnWidth: Int = 620, sampleCap: Int = 250): ColumnFit =
        ColumnFit(table, maxColumnWidth, sampleCap).also { it.install() }
}
