package no.nav.appsecguide.infrastructure.cisa

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.cache.ValkeyCache
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import kotlin.time.Duration.Companion.minutes

private var valkeyContainer: GenericContainer<*>? = null
private var kevCache: ValkeyCache<String, KevCatalog>? = null

fun getOrCreateTestValkeyContainer(): GenericContainer<*> {
    if (valkeyContainer == null) {
        valkeyContainer = GenericContainer(DockerImageName.parse("ghcr.io/valkey-io/valkey:7.2-alpine"))
            .withExposedPorts(6379)
        valkeyContainer!!.start()
    }
    return valkeyContainer!!
}

fun getOrCreateKevCache(): ValkeyCache<String, KevCatalog> {
    if (kevCache == null) {
        val container = getOrCreateTestValkeyContainer()
        val host = container.host
        val port = container.getMappedPort(6379)
        val valkeyUri = "redis://$host:$port"

        val poolConfig = io.valkey.JedisPoolConfig().apply {
            maxTotal = 20
            maxIdle = 10
            minIdle = 5
        }
        val pool = io.valkey.JedisPool(poolConfig, java.net.URI.create(valkeyUri))

        kevCache = ValkeyCache(
            pool = pool,
            ttl = 5.minutes,
            keyPrefix = "kev-test",
            valueSerializer = KevCatalog.serializer()
        )
    }
    return kevCache!!
}

fun createMockCachedKevService(mockCatalog: KevCatalog? = null): CachedKevService {
    val catalog = mockCatalog ?: KevCatalog(
        title = "CISA Catalog of Known Exploited Vulnerabilities",
        catalogVersion = "2025.11.19",
        dateReleased = "2025-11-19T18:00:42.0859Z",
        count = 1,
        vulnerabilities = listOf(
            KevVulnerability(
                cveID = "CVE-2025-13223",
                vendorProject = "Google",
                product = "Chromium V8",
                vulnerabilityName = "Google Chromium V8 Type Confusion Vulnerability",
                dateAdded = "2025-11-19",
                shortDescription = "Google Chromium V8 contains a type confusion vulnerability that allows for heap corruption.",
                requiredAction = "Apply mitigations per vendor instructions, follow applicable BOD 22-01 guidance for cloud services, or discontinue use of the product if mitigations are unavailable.",
                dueDate = "2025-12-10",
                knownRansomwareCampaignUse = "Unknown",
                notes = "https://chromereleases.googleblog.com/2025/11/stable-channel-update-for-desktop_17.html",
                cwes = listOf("CWE-843")
            )
        )
    )

    val mockEngine = MockEngine { _ ->
        respond(
            content = Json.encodeToString(KevCatalog.serializer(), catalog),
            status = HttpStatusCode.OK,
            headers = headersOf(HttpHeaders.ContentType, "application/json")
        )
    }

    val httpClient = HttpClient(mockEngine) {
        install(ContentNegotiation) {
            json(Json { ignoreUnknownKeys = true })
        }
    }

    val kevClient = KevClient(httpClient, "http://mock-kev")
    val cache = getOrCreateKevCache()

    return CachedKevService(kevClient, cache)
}

