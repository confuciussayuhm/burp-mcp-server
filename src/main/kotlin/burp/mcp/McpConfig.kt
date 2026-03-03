package burp.mcp

import burp.api.montoya.logging.Logging
import burp.api.montoya.persistence.PersistedObject
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

class McpConfig(storage: PersistedObject, private val logging: Logging) {

    var enabled by storage.boolean(true)
    var configEditingTooling by storage.boolean(false)
    var host by storage.string("127.0.0.1")
    var port by storage.int(9876)
    var requireHttpRequestApproval by storage.boolean(true)
    var requireHistoryAccessApproval by storage.boolean(true)
    private var _alwaysAllowHttpHistory by storage.boolean(false, key = "alwaysAllowHttpHistory")
    private var _alwaysAllowWebSocketHistory by storage.boolean(false, key = "alwaysAllowWebSocketHistory")

    var onAlwaysAllowHistoryChanged: (() -> Unit)? = null

    var alwaysAllowHttpHistory: Boolean
        get() = _alwaysAllowHttpHistory
        set(value) { _alwaysAllowHttpHistory = value; onAlwaysAllowHistoryChanged?.invoke() }

    var alwaysAllowWebSocketHistory: Boolean
        get() = _alwaysAllowWebSocketHistory
        set(value) { _alwaysAllowWebSocketHistory = value; onAlwaysAllowHistoryChanged?.invoke() }

    private var _autoApproveTargets by storage.string("")

    var onAutoApproveTargetsChanged: (() -> Unit)? = null

    var autoApproveTargets: String
        get() = _autoApproveTargets
        set(value) {
            _autoApproveTargets = value
            onAutoApproveTargetsChanged?.invoke()
        }

    fun getAutoApproveTargetsList(): List<String> {
        return if (_autoApproveTargets.isBlank()) {
            emptyList()
        } else {
            _autoApproveTargets.split(",").map { it.trim() }.filter { it.isNotEmpty() }
        }
    }

    fun addAutoApproveTarget(target: String): Boolean {
        val current = getAutoApproveTargetsList()
        val trimmed = target.trim()
        if (trimmed.isNotEmpty() && trimmed !in current) {
            autoApproveTargets = (current + trimmed).joinToString(",")
            return true
        }
        return false
    }

    fun removeAutoApproveTargets(targets: Collection<String>): Boolean {
        val current = getAutoApproveTargetsList()
        val toRemove = targets.map { it.trim() }.toSet()
        val filtered = current.filter { it !in toRemove }
        if (filtered.size != current.size) {
            autoApproveTargets = filtered.joinToString(",")
            return true
        }
        return false
    }

    fun cleanup() {
        onAutoApproveTargetsChanged = null
        onAlwaysAllowHistoryChanged = null
    }
}

fun PersistedObject.boolean(default: Boolean = false, key: String? = null) =
    PersistedDelegate(
        getter = { propName -> getBoolean(key ?: propName) ?: default },
        setter = { propName, value -> setBoolean(key ?: propName, value) }
    )

fun PersistedObject.string(default: String) =
    PersistedDelegate(getter = { key -> getString(key) ?: default }, setter = { key, value -> setString(key, value) })

fun PersistedObject.int(default: Int) =
    PersistedDelegate(getter = { key -> getInteger(key) ?: default }, setter = { key, value -> setInteger(key, value) })

class PersistedDelegate<T>(
    private val getter: (name: String) -> T,
    private val setter: (name: String, value: T) -> Unit
) : ReadWriteProperty<Any, T> {
    override fun getValue(thisRef: Any, property: KProperty<*>) = getter(property.name)
    override fun setValue(thisRef: Any, property: KProperty<*>, value: T) = setter(property.name, value)
}
