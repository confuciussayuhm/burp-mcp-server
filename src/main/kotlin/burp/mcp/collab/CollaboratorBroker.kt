package burp.mcp.collab

import burp.api.montoya.MontoyaApi
import burp.api.montoya.collaborator.CollaboratorClient
import burp.api.montoya.collaborator.CollaboratorPayload
import burp.api.montoya.collaborator.Interaction
import burp.api.montoya.collaborator.SecretKey
import burp.api.montoya.persistence.PersistedObject

/**
 * Owns the one Burp Collaborator client that every MCP tool call shares.
 *
 * The MCP transport is stateless: `mcpStatelessStreamableHttp` builds a fresh [Server] and re-runs
 * tool registration for every HTTP POST. A Collaborator client held in a `by lazy` local inside that
 * registration is therefore rebuilt per tool call, and `Collaborator.createClient()` mints a brand
 * new secret key each time. `getAllInteractions()` only ever returns interactions "resulting from
 * payloads that were generated for this client", so the client doing the polling had never generated
 * the payload being polled for and the poll always came back empty — a guaranteed false negative,
 * even when the payload host had demonstrably been hit.
 *
 * One client per extension load fixes that. Persisting its secret key and coming back through
 * `Collaborator.restoreClient` also keeps payloads pollable across extension reloads and Burp
 * restarts, which is when OOB findings usually get confirmed: well after the payload went out.
 */
class CollaboratorBroker(
    private val api: MontoyaApi,
    private val persistence: PersistedObject? = null
) {

    private val lock = Any()

    @Volatile
    private var client: CollaboratorClient? = null

    /**
     * Payloads handed out so far, newest last. Only used to tell the caller what a poll actually
     * covered — an empty result means something very different depending on whether this client has
     * ever issued a payload.
     */
    private val payloads = LinkedHashSet<String>()

    /** Every interaction retrieved so far, keyed by [cacheKey], oldest first. See [poll]. */
    private val seen = LinkedHashMap<String, Interaction>()

    init {
        persistence?.getString(K_PAYLOADS)?.takeIf { it.isNotBlank() }?.let { blob ->
            payloads.addAll(blob.split(',').filter { it.isNotBlank() })
        }
    }

    /**
     * The shared client, restored from the persisted secret key when there is one.
     *
     * @throws CollaboratorUnavailable if Burp Collaborator is disabled or otherwise unusable.
     */
    fun client(): CollaboratorClient {
        client?.let { return it }
        synchronized(lock) {
            client?.let { return it }
            val created = restoreOrCreate()
            client = created
            return created
        }
    }

    private fun restoreOrCreate(): CollaboratorClient {
        val stored = persistence?.getString(K_SECRET_KEY)?.takeIf { it.isNotBlank() }
        if (stored != null) {
            try {
                val restored = api.collaborator().restoreClient(SecretKey.secretKey(stored))
                api.logging().logToOutput(
                    "MCP restored Collaborator client (${payloads.size} payload(s) still tracked)"
                )
                return restored
            } catch (e: Exception) {
                // Stale key, or the Collaborator server config changed since it was written. Start
                // over rather than leaving Collaborator broken for the rest of the session.
                api.logging().logToError(
                    "MCP could not restore the stored Collaborator client (${e.message}); creating a new one. " +
                        "Payloads generated before now will no longer be pollable."
                )
                payloads.clear()
                persistence?.setString(K_PAYLOADS, "")
            }
        }

        val created = try {
            api.collaborator().createClient()
        } catch (e: Exception) {
            throw CollaboratorUnavailable(e)
        }
        try {
            persistence?.setString(K_SECRET_KEY, created.secretKey.toString())
        } catch (e: Exception) {
            api.logging().logToError("MCP could not persist the Collaborator secret key: ${e.message}")
        }
        api.logging().logToOutput("MCP created a new Collaborator client")
        return created
    }

    /** Generates a payload and records it so [poll] can report what it is covering. */
    fun generatePayload(customData: String?): CollaboratorPayload {
        val c = client()
        val payload = guard {
            if (customData != null) c.generatePayload(customData) else c.generatePayload()
        }
        synchronized(lock) {
            payloads.add(payload.toString())
            while (payloads.size > MAX_TRACKED_PAYLOADS) {
                payloads.remove(payloads.first())
            }
            persistence?.setString(K_PAYLOADS, payloads.joinToString(","))
        }
        return payload
    }

    /**
     * Polls for interactions, optionally narrowed to one payload. Results are cumulative: every
     * interaction this client has ever seen for the payload, not just the ones that arrived since
     * the last call.
     *
     * The Collaborator server hands each interaction to a client exactly once — a second poll comes
     * back empty even though the payload was hit. Left alone that reads as a retraction, and an
     * agent that polls twice while writing up a blind injection talks itself out of a real finding.
     * So every retrieval is cached here and re-served on later polls.
     *
     * For the same reason this always drains with `getAllInteractions()` and filters locally, never
     * with `getInteractions(filter)`: the filtered call still consumes everything the server is
     * holding but returns only the matches, silently destroying interactions belonging to every
     * other payload in flight.
     *
     * [payloadId] is accepted in any of the forms a caller is likely to have to hand: the bare
     * interaction id (`abc123`), the full payload (`abc123.oastify.com`), or the payload with the
     * prefix labels an injection usually adds (`exfil.abc123.oastify.com`). Matching on labels
     * rather than passing the string straight to `interactionIdFilter` is what makes the last two
     * work — an agent that read "Payload:" out of `generate_collaborator_payload` would otherwise
     * filter on a value no interaction can ever carry and see nothing.
     */
    fun poll(payloadId: String?): List<Interaction> {
        val c = client()
        val fresh = guard { c.allInteractions }

        val wanted = payloadId?.trim()?.lowercase()?.takeIf { it.isNotEmpty() }
        val labels = wanted?.split('.')?.filter { it.isNotEmpty() }?.toSet().orEmpty()

        synchronized(lock) {
            for (i in fresh) seen.putIfAbsent(cacheKey(i), i)
            while (seen.size > MAX_CACHED_INTERACTIONS) {
                seen.remove(seen.keys.first())
            }
            val all = seen.values.sortedBy { it.timeStamp() }
            return if (wanted == null) all else all.filter {
                val id = it.id().toString().lowercase()
                id == wanted || id in labels
            }
        }
    }

    /**
     * Interaction.id() is the payload id, shared by every interaction against that payload, so it
     * cannot identify one on its own — the arrival details are what make each hit distinct.
     */
    private fun cacheKey(i: Interaction): String =
        "${i.id()}|${i.type()}|${i.timeStamp()}|${i.clientIp().hostAddress}|${i.clientPort()}"

    fun serverAddress(): String = guard { client().server().address() }

    /** Payloads this client has issued, newest last. */
    fun trackedPayloads(): List<String> = synchronized(lock) { payloads.toList() }

    /**
     * Burp throws [IllegalStateException] from every Collaborator call when Collaborator is
     * disabled, generally with no message. Turn that into something a caller can act on.
     */
    private inline fun <T> guard(body: () -> T): T = try {
        body()
    } catch (e: CollaboratorUnavailable) {
        throw e
    } catch (e: IllegalStateException) {
        throw CollaboratorUnavailable(e)
    }

    companion object {
        private const val K_SECRET_KEY = "collaborator.secretKey"
        private const val K_PAYLOADS = "collaborator.payloads"
        private const val MAX_TRACKED_PAYLOADS = 500
        private const val MAX_CACHED_INTERACTIONS = 5000
    }
}

class CollaboratorUnavailable(cause: Throwable) : IllegalStateException(
    "Burp Collaborator is not available. Check Settings > Project > Collaborator: it is disabled, " +
        "or the configured Collaborator server cannot be reached." +
        (cause.message?.let { " (Burp reported: $it)" } ?: ""),
    cause
)
