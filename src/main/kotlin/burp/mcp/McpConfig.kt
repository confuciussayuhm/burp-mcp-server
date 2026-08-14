package burp.mcp

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

/**
 * What changed, so a listener can decide how much of the UI to rebuild and whether the
 * pending-approval queue needs reconciling against the new rules.
 */
enum class ConfigChange {
    AUTO_APPROVE_TARGETS,
    CONFIG_EDITING_TOOLING,
    REQUIRE_HTTP_REQUEST_APPROVAL,
    REQUIRE_HISTORY_ACCESS_APPROVAL,
    USE_BURP_SCOPE,
    AUTO_APPROVE_ALL_NEW_TARGETS,
    ALWAYS_ALLOW_HTTP_HISTORY,
    ALWAYS_ALLOW_WEBSOCKET_HISTORY,
    SERVER_BINDING;

    /** True for the seven toggles that make up the Security card. */
    val isSecurityRule: Boolean
        get() = this != SERVER_BINDING && this != AUTO_APPROVE_TARGETS
}

class McpConfig(private val storage: PersistedObject, private val logging: Logging) {

    var enabled by BoolPref(K_ENABLED, true, null)
    var host by StringPref(K_HOST, "127.0.0.1", ConfigChange.SERVER_BINDING)
    var port by IntPref(K_PORT, 9876, ConfigChange.SERVER_BINDING)

    // --- Security rules ------------------------------------------------------------------
    // Defaults below are the conservative, network-reachable defaults. On a brand new project
    // bound to loopback they are overridden to "all on" once, in init — see applyFirstRunSecurityDefaults.

    var configEditingTooling by BoolPref(K_CONFIG_EDITING, false, ConfigChange.CONFIG_EDITING_TOOLING)
    var requireHttpRequestApproval by BoolPref(K_REQUIRE_HTTP, true, ConfigChange.REQUIRE_HTTP_REQUEST_APPROVAL)
    var requireHistoryAccessApproval by BoolPref(K_REQUIRE_HISTORY, true, ConfigChange.REQUIRE_HISTORY_ACCESS_APPROVAL)
    var useBurpScopeForApproval by BoolPref(K_USE_BURP_SCOPE, true, ConfigChange.USE_BURP_SCOPE)
    var autoApproveAllNewTargets by BoolPref(K_AUTO_APPROVE_ALL, false, ConfigChange.AUTO_APPROVE_ALL_NEW_TARGETS)
    var alwaysAllowHttpHistory by BoolPref(K_ALWAYS_HTTP_HISTORY, false, ConfigChange.ALWAYS_ALLOW_HTTP_HISTORY)
    var alwaysAllowWebSocketHistory by BoolPref(K_ALWAYS_WS_HISTORY, false, ConfigChange.ALWAYS_ALLOW_WEBSOCKET_HISTORY)

    private var _autoApproveTargets by StringPref(K_AUTO_APPROVE_TARGETS, "", null)

    // --- Listeners -----------------------------------------------------------------------

    private val listeners = CopyOnWriteArrayList<(ConfigChange) -> Unit>()

    /** Registers a listener and returns the function that unregisters it. */
    fun addListener(listener: (ConfigChange) -> Unit): () -> Unit {
        listeners.add(listener)
        return { listeners.remove(listener) }
    }

    private fun fire(change: ConfigChange) {
        for (listener in listeners) {
            try {
                listener(change)
            } catch (e: Exception) {
                logging.logToError("MCP config listener failed for $change: ${e.message}")
            }
        }
    }

    // --- Auto-approved targets -----------------------------------------------------------

    // The parsed view of _autoApproveTargets. Every HTTP request the server gates reads this
    // list, so re-splitting the comma-joined string each time is real work on the hot path —
    // especially with capture mode on, which is the loopback default.
    @Volatile
    private var targetsCache: List<String>? = null

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            synchronized(this) {
                if (_autoApproveTargets == value) return
                _autoApproveTargets = value
                targetsCache = null
            }
            fire(ConfigChange.AUTO_APPROVE_TARGETS)
        }

    fun getAutoApproveTargetsList(): List<String> {
        targetsCache?.let { return it }
        return synchronized(this) {
            targetsCache ?: parseTargets(_autoApproveTargets).also { targetsCache = it }
        }
    }

    private fun parseTargets(raw: String): List<String> =
        if (raw.isBlank()) emptyList()
        else raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }

    fun addAutoApproveTarget(target: String): Boolean {
        val trimmed = target.trim()
        if (trimmed.isEmpty()) return false
        synchronized(this) {
            val current = getAutoApproveTargetsList()
            if (current.any { it.equals(trimmed, ignoreCase = true) }) return false
            val updated = current + trimmed
            _autoApproveTargets = updated.joinToString(",")
            targetsCache = updated
        }
        fire(ConfigChange.AUTO_APPROVE_TARGETS)
        return true
    }

    fun removeAutoApproveTargets(targets: Collection<String>): Boolean {
        val toRemove = targets.map { it.trim().lowercase() }.toSet()
        synchronized(this) {
            val current = getAutoApproveTargetsList()
            val filtered = current.filter { it.lowercase() !in toRemove }
            if (filtered.size == current.size) return false
            _autoApproveTargets = filtered.joinToString(",")
            targetsCache = filtered
        }
        fire(ConfigChange.AUTO_APPROVE_TARGETS)
        return true
    }

    // --- Loopback security defaults ------------------------------------------------------

    /** True when the server is bound to an address only reachable from this machine. */
    fun isLoopbackBind(): Boolean = isLoopbackHost(host)

    /**
     * Turns every Security rule on. Used for the first-run loopback default and by the
     * "Restore loopback defaults" button.
     */
    fun enableAllSecurityRules() {
        configEditingTooling = true
        requireHttpRequestApproval = true
        requireHistoryAccessApproval = true
        useBurpScopeForApproval = true
        autoApproveAllNewTargets = true
        alwaysAllowHttpHistory = true
        alwaysAllowWebSocketHistory = true
    }

    /**
     * On a project that has never seen these settings, a loopback bind means the server is
     * only reachable from this machine, so every Security rule starts ticked. The values are
     * materialised into the project store exactly once — after that the persisted choice
     * always wins, so changing the bind host later never rewrites a rule the user set by hand.
     */
    private fun applyFirstRunSecurityDefaults() {
        if (storage.getBoolean(K_DEFAULTS_APPLIED) == true) return
        storage.setBoolean(K_DEFAULTS_APPLIED, true)

        if (!isLoopbackHost(storage.getString(K_HOST) ?: "127.0.0.1")) return

        var applied = 0
        for (key in SECURITY_RULE_KEYS) {
            if (storage.getBoolean(key) == null) {
                storage.setBoolean(key, true)
                applied++
            }
        }
        if (applied > 0) {
            logging.logToOutput(
                "MCP Server: loopback bind — all $applied security rules enabled by default " +
                    "(change them under MCP → Server → Security)"
            )
        }
    }

    fun cleanup() {
        listeners.clear()
    }

    init {
        applyFirstRunSecurityDefaults()
    }

    // --- Persisted property delegates ----------------------------------------------------

    private inner class BoolPref(
        private val key: String,
        private val default: Boolean,
        private val change: ConfigChange?
    ) : ReadWriteProperty<Any?, Boolean> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): Boolean =
            storage.getBoolean(key) ?: default

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: Boolean) {
            val changed = (storage.getBoolean(key) ?: default) != value
            storage.setBoolean(key, value)
            if (changed && change != null) fire(change)
        }
    }

    private inner class StringPref(
        private val key: String,
        private val default: String,
        private val change: ConfigChange?
    ) : ReadWriteProperty<Any?, String> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): String =
            storage.getString(key) ?: default

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: String) {
            val changed = (storage.getString(key) ?: default) != value
            storage.setString(key, value)
            if (changed && change != null) fire(change)
        }
    }

    private inner class IntPref(
        private val key: String,
        private val default: Int,
        private val change: ConfigChange?
    ) : ReadWriteProperty<Any?, Int> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): Int =
            storage.getInteger(key) ?: default

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: Int) {
            val changed = (storage.getInteger(key) ?: default) != value
            storage.setInteger(key, value)
            if (changed && change != null) fire(change)
        }
    }

    companion object {
        // Persistence keys. Kept as constants because applyFirstRunSecurityDefaults writes
        // them directly, so a typo would silently stop the loopback default from applying.
        private const val K_ENABLED = "enabled"
        private const val K_HOST = "host"
        private const val K_PORT = "port"
        private const val K_CONFIG_EDITING = "configEditingTooling"
        private const val K_REQUIRE_HTTP = "requireHttpRequestApproval"
        private const val K_REQUIRE_HISTORY = "requireHistoryAccessApproval"
        private const val K_USE_BURP_SCOPE = "useBurpScopeForApproval"
        private const val K_AUTO_APPROVE_ALL = "autoApproveAllNewTargets"
        private const val K_ALWAYS_HTTP_HISTORY = "alwaysAllowHttpHistory"
        private const val K_ALWAYS_WS_HISTORY = "alwaysAllowWebSocketHistory"
        private const val K_AUTO_APPROVE_TARGETS = "_autoApproveTargets"
        private const val K_DEFAULTS_APPLIED = "securityDefaultsApplied"

        private val SECURITY_RULE_KEYS = listOf(
            K_CONFIG_EDITING,
            K_REQUIRE_HTTP,
            K_REQUIRE_HISTORY,
            K_USE_BURP_SCOPE,
            K_AUTO_APPROVE_ALL,
            K_ALWAYS_HTTP_HISTORY,
            K_ALWAYS_WS_HISTORY
        )

        fun isLoopbackHost(host: String): Boolean {
            val h = host.trim().lowercase().removeSurrounding("[", "]")
            if (h == "localhost" || h == "::1" || h == "0:0:0:0:0:0:0:1") return true
            return h.startsWith("127.")
        }
    }
}
