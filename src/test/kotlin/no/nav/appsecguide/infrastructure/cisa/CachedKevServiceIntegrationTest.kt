package no.nav.appsecguide.infrastructure.cisa

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.cache.ValkeyCache
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.testcontainers.containers.GenericContainer
import org.testcontainers.utility.DockerImageName
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.minutes

class CachedKevServiceIntegrationTest {

    companion object {
        private lateinit var valkeyContainer: GenericContainer<*>
        private lateinit var cache: ValkeyCache<String, KevCatalog>

        @JvmStatic
        @BeforeAll
        fun setup() {
            valkeyContainer = GenericContainer(DockerImageName.parse("ghcr.io/valkey-io/valkey:7.2-alpine"))
                .withExposedPorts(6379)
            valkeyContainer.start()

            val host = valkeyContainer.host
            val port = valkeyContainer.getMappedPort(6379)
            val valkeyUri = "redis://$host:$port"

            val pool = createTestValkeyPool(valkeyUri)
            cache = ValkeyCache(
                pool = pool,
                ttl = 5.minutes,
                keyPrefix = "kev-test",
                valueSerializer = KevCatalog.serializer()
            )
        }

        private fun createTestValkeyPool(uri: String): io.valkey.JedisPool {
            val valkeyUri = java.net.URI.create(uri)
            val poolConfig = io.valkey.JedisPoolConfig().apply {
                maxTotal = 20
                maxIdle = 10
                minIdle = 5
            }
            return io.valkey.JedisPool(poolConfig, valkeyUri)
        }

        @JvmStatic
        @AfterAll
        fun teardown() {
            cache.close()
            valkeyContainer.stop()
        }
    }

    @Test
    fun `should cache KEV catalog responses`() = runTest {
        cache.clear()
        var apiCallCount = 0

        val mockEngine = MockEngine { request ->
            apiCallCount++
            respond(
                content = """
                    {
                        "title": "CISA Catalog of Known Exploited Vulnerabilities",
                        "catalogVersion": "2025.11.19",
                        "dateReleased": "2025-11-19T18:00:42.0859Z",
                        "count": 2,
                        "vulnerabilities": [
                            {
                                "cveID": "CVE-2025-13223",
                                "vendorProject": "Google",
                                "product": "Chromium V8",
                                "vulnerabilityName": "Google Chromium V8 Type Confusion Vulnerability",
                                "dateAdded": "2025-11-19",
                                "shortDescription": "Google Chromium V8 contains a type confusion vulnerability.",
                                "requiredAction": "Apply mitigations per vendor instructions.",
                                "dueDate": "2025-12-10",
                                "knownRansomwareCampaignUse": "Unknown",
                                "notes": "https://chromereleases.googleblog.com/2025/11/stable-channel-update-for-desktop_17.html",
                                "cwes": ["CWE-843"]
                            },
                            {
                                "cveID": "CVE-2025-13224",
                                "vendorProject": "Microsoft",
                                "product": "Windows",
                                "vulnerabilityName": "Microsoft Windows Privilege Escalation Vulnerability",
                                "dateAdded": "2025-11-19",
                                "shortDescription": "Microsoft Windows contains a privilege escalation vulnerability.",
                                "requiredAction": "Apply updates per vendor instructions.",
                                "dueDate": "2025-12-10",
                                "knownRansomwareCampaignUse": "Known",
                                "notes": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-13224",
                                "cwes": ["CWE-269"]
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val kevClient = KevClient(httpClient, "http://test/kev.json")
        val cachedService = CachedKevService(kevClient, cache)

        val catalog1 = cachedService.getKevCatalog()
        val catalog2 = cachedService.getKevCatalog()
        val catalog3 = cachedService.getKevCatalog()

        assertEquals(1, apiCallCount, "API should only be called once due to caching")
        assertEquals(2, catalog1.count)
        assertEquals(2, catalog2.count)
        assertEquals(2, catalog3.count)
        assertEquals(2, catalog1.vulnerabilities.size)
        assertEquals("CVE-2025-13223", catalog1.vulnerabilities[0].cveID)
        assertEquals("CVE-2025-13224", catalog1.vulnerabilities[1].cveID)
    }

    @Test
    fun `should parse KEV catalog correctly`() = runTest {
        cache.clear()

        val mockEngine = MockEngine { request ->
            respond(
                content = """
                    {
                        "title": "CISA Catalog of Known Exploited Vulnerabilities",
                        "catalogVersion": "2025.11.19",
                        "dateReleased": "2025-11-19T18:00:42.0859Z",
                        "count": 1,
                        "vulnerabilities": [
                            {
                                "cveID": "CVE-2025-13223",
                                "vendorProject": "Google",
                                "product": "Chromium V8",
                                "vulnerabilityName": "Google Chromium V8 Type Confusion Vulnerability",
                                "dateAdded": "2025-11-19",
                                "shortDescription": "Google Chromium V8 contains a type confusion vulnerability.",
                                "requiredAction": "Apply mitigations per vendor instructions.",
                                "dueDate": "2025-12-10",
                                "knownRansomwareCampaignUse": "Unknown",
                                "notes": "https://chromereleases.googleblog.com/2025/11/stable-channel-update-for-desktop_17.html",
                                "cwes": ["CWE-843"]
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val kevClient = KevClient(httpClient, "http://test/kev.json")
        val cachedService = CachedKevService(kevClient, cache)

        val catalog = cachedService.getKevCatalog()

        assertEquals("CISA Catalog of Known Exploited Vulnerabilities", catalog.title)
        assertEquals("2025.11.19", catalog.catalogVersion)
        assertEquals(1, catalog.count)
        assertEquals(1, catalog.vulnerabilities.size)

        val vuln = catalog.vulnerabilities[0]
        assertEquals("CVE-2025-13223", vuln.cveID)
        assertEquals("Google", vuln.vendorProject)
        assertEquals("Chromium V8", vuln.product)
        assertEquals("Google Chromium V8 Type Confusion Vulnerability", vuln.vulnerabilityName)
        assertEquals("2025-11-19", vuln.dateAdded)
        assertEquals("2025-12-10", vuln.dueDate)
        assertEquals("Unknown", vuln.knownRansomwareCampaignUse)
        assertTrue(vuln.shortDescription.isNotEmpty())
        assertTrue(vuln.requiredAction.isNotEmpty())
        assertTrue(vuln.cwes.contains("CWE-843"))
    }

    @Test
    fun `should use date-based cache key`() = runTest {
        cache.clear()
        var apiCallCount = 0

        val mockEngine = MockEngine { request ->
            apiCallCount++
            respond(
                content = """
                    {
                        "title": "CISA Catalog of Known Exploited Vulnerabilities",
                        "catalogVersion": "2025.11.19",
                        "dateReleased": "2025-11-19T18:00:42.0859Z",
                        "count": 0,
                        "vulnerabilities": []
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val kevClient = KevClient(httpClient, "http://test/kev.json")
        val cachedService = CachedKevService(kevClient, cache)

        cachedService.getKevCatalog()
        cachedService.getKevCatalog()

        assertEquals(1, apiCallCount, "Multiple calls on same day should use cached data")
    }

    @Test
    fun `should use cached data when calling getKevForCve`() = runTest {
        cache.clear()
        var apiCallCount = 0

        val mockEngine = MockEngine { request ->
            apiCallCount++
            respond(
                content = """
                    {
                        "title": "CISA Catalog of Known Exploited Vulnerabilities",
                        "catalogVersion": "2025.11.19",
                        "dateReleased": "2025-11-19T18:00:42.0859Z",
                        "count": 2,
                        "vulnerabilities": [
                            {
                                "cveID": "CVE-2025-13223",
                                "vendorProject": "Google",
                                "product": "Chromium V8",
                                "vulnerabilityName": "Google Chromium V8 Type Confusion Vulnerability",
                                "dateAdded": "2025-11-19",
                                "shortDescription": "Test description",
                                "requiredAction": "Test action",
                                "dueDate": "2025-12-10",
                                "knownRansomwareCampaignUse": "Unknown",
                                "notes": "Test notes",
                                "cwes": ["CWE-843"]
                            },
                            {
                                "cveID": "CVE-2025-99999",
                                "vendorProject": "Test Vendor",
                                "product": "Test Product",
                                "vulnerabilityName": "Test Vulnerability",
                                "dateAdded": "2025-11-19",
                                "shortDescription": "Test description 2",
                                "requiredAction": "Test action 2",
                                "dueDate": "2025-12-10",
                                "knownRansomwareCampaignUse": "Known",
                                "notes": "Test notes 2",
                                "cwes": ["CWE-123"]
                            }
                        ]
                    }
                """.trimIndent(),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val kevClient = KevClient(httpClient, "http://test/kev.json")
        val cachedService = CachedKevService(kevClient, cache)

        val vuln1 = cachedService.getKevForCve("CVE-2025-13223")
        val vuln2 = cachedService.getKevForCve("CVE-2025-99999")
        val vuln3 = cachedService.getKevForCve("CVE-2025-13223")
        val vulnNotFound = cachedService.getKevForCve("CVE-9999-99999")

        assertEquals(1, apiCallCount, "Multiple getKevForCve calls should use cached catalog")
        assertEquals("CVE-2025-13223", vuln1?.cveID)
        assertEquals("Google", vuln1?.vendorProject)
        assertEquals("CVE-2025-99999", vuln2?.cveID)
        assertEquals("Test Vendor", vuln2?.vendorProject)
        assertEquals("CVE-2025-13223", vuln3?.cveID)
        assertEquals(null, vulnNotFound)
    }
}

