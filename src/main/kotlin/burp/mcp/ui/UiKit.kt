package burp.mcp.ui

import java.awt.AlphaComposite
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.Cursor
import java.awt.Dimension
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
import javax.swing.JPanel
import javax.swing.JPopupMenu
import javax.swing.Timer
import javax.swing.UIManager
import javax.swing.border.EmptyBorder

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
}
