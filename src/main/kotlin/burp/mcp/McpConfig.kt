package burp.mcp

import burp.api.montoya.persistence.PersistedObject
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KProperty

class McpConfig(private val storage: PersistedObject) {

    var enabled by BoolPref("enabled", true)
    var host by StringPref("host", "127.0.0.1")
    var port by IntPref("port", 9876)

    // --- Persisted property delegates ----------------------------------------------------

    private inner class BoolPref(
        private val key: String,
        private val default: Boolean
    ) : ReadWriteProperty<Any?, Boolean> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): Boolean =
            storage.getBoolean(key) ?: default

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: Boolean) =
            storage.setBoolean(key, value)
    }

    private inner class StringPref(
        private val key: String,
        private val default: String
    ) : ReadWriteProperty<Any?, String> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): String =
            storage.getString(key) ?: default

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: String) =
            storage.setString(key, value)
    }

    private inner class IntPref(
        private val key: String,
        private val default: Int
    ) : ReadWriteProperty<Any?, Int> {
        override fun getValue(thisRef: Any?, property: KProperty<*>): Int =
            storage.getInteger(key) ?: default

        override fun setValue(thisRef: Any?, property: KProperty<*>, value: Int) =
            storage.setInteger(key, value)
    }
}
