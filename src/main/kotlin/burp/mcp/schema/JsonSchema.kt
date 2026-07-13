package burp.mcp.schema

import io.modelcontextprotocol.kotlin.sdk.types.ToolSchema
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.reflect.KClass
import kotlin.reflect.full.memberProperties

fun getJsonSchemaForProperty(kType: kotlin.reflect.KType): JsonElement {
    return when (kType.classifier) {
        String::class ->
            JsonObject(mapOf("type" to JsonPrimitive("string")))

        Int::class, Long::class ->
            JsonObject(mapOf("type" to JsonPrimitive("integer")))

        Float::class, Double::class ->
            JsonObject(mapOf("type" to JsonPrimitive("number")))

        Boolean::class ->
            JsonObject(mapOf("type" to JsonPrimitive("boolean")))

        List::class, Array::class -> {
            val argType = kType.arguments.firstOrNull()?.type
            val itemsSchema = when {
                argType != null -> getJsonSchemaForProperty(argType)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
            JsonObject(mapOf("type" to JsonPrimitive("array"), "items" to itemsSchema))
        }

        Map::class -> {
            val valueType = kType.arguments.getOrNull(1)?.type
            val valueSchema = when {
                valueType != null -> getJsonSchemaForProperty(valueType)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
            JsonObject(mapOf("type" to JsonPrimitive("object"), "additionalProperties" to valueSchema))
        }

        else -> {
            val klass = kType.classifier as? KClass<*>
            when {
                klass == null -> JsonObject(mapOf("type" to JsonPrimitive("object")))
                // Enums become a string constrained to the enum's constant names.
                klass.java.isEnum -> {
                    val values = klass.java.enumConstants.orEmpty().map { JsonPrimitive((it as Enum<*>).name) }
                    JsonObject(mapOf("type" to JsonPrimitive("string"), "enum" to JsonArray(values)))
                }
                // Nested data classes (e.g. Replacement, ParamUpdate) recurse into a full object
                // schema instead of the opaque bare {"type":"object"} that hid their fields.
                klass.isData -> objectSchema(klass)
                else -> JsonObject(mapOf("type" to JsonPrimitive("object")))
            }
        }
    }
}

private fun objectSchema(klass: KClass<*>): JsonObject {
    val properties = mutableMapOf<String, JsonElement>()
    val required = mutableListOf<String>()
    for (prop in klass.memberProperties) {
        properties[prop.name] = getJsonSchemaForProperty(prop.returnType)
        if (!prop.returnType.isMarkedNullable) required.add(prop.name)
    }
    return JsonObject(
        mapOf(
            "type" to JsonPrimitive("object"),
            "properties" to JsonObject(properties),
            "required" to JsonArray(required.map { JsonPrimitive(it) })
        )
    )
}

fun KClass<*>.asInputSchema(): ToolSchema {
    val properties = mutableMapOf<String, JsonElement>()
    val required = mutableListOf<String>()

    for (prop in memberProperties) {
        properties[prop.name] = getJsonSchemaForProperty(prop.returnType)

        if (!prop.returnType.isMarkedNullable) {
            required.add(prop.name)
        }
    }

    return ToolSchema(
        properties = JsonObject(properties),
        required = required
    )
}
