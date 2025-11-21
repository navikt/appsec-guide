package no.nav.appsecguide.infrastructure.epss

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.cache.Cache
import kotlin.test.*

class CachedEpssServiceTest {

    private class InMemoryCache<K, V> : Cache<K, V> {
        private val storage = mutableMapOf<K, V>()

        override suspend fun get(key: K): V? = storage[key]
        override suspend fun put(key: K, value: V) {
            storage[key] = value
        }
        override suspend fun getOrPut(key: K, provider: suspend () -> V): V {
            return get(key) ?: provider().also { put(key, it) }
        }
        override suspend fun invalidate(key: K) {
            storage.remove(key)
        }
        override suspend fun clear() {
            storage.clear()
        }
    }

    @Test
    fun `should fetch and cache EPSS scores`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { _ ->
            requestCount++
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2025-11-20"
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

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val result1 = service.getEpssScores(listOf("CVE-2021-44228"))
        assertEquals(1, result1.size)
        assertEquals("0.942510000", result1["CVE-2021-44228"]?.epss)
        assertEquals(1, requestCount)

        val result2 = service.getEpssScores(listOf("CVE-2021-44228"))
        assertEquals(1, result2.size)
        assertEquals("0.942510000", result2["CVE-2021-44228"]?.epss)
        assertEquals(1, requestCount)
    }

    @Test
    fun `should use different cache keys for different CVE sets`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { _ ->
            requestCount++
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 1,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2025-11-20"
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

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        service.getEpssScores(listOf("CVE-2021-44228"))
        assertEquals(1, requestCount)

        service.getEpssScores(listOf("CVE-2022-22965"))
        assertEquals(2, requestCount)
    }

    @Test
    fun `should use same cache key for same CVEs in different order`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { _ ->
            requestCount++
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 2,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2025-11-20"
                            },
                            {
                                "cve": "CVE-2022-22965",
                                "epss": "0.943870000",
                                "percentile": "0.999930000",
                                "date": "2025-11-20"
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

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        service.getEpssScores(listOf("CVE-2021-44228", "CVE-2022-22965"))
        assertEquals(1, requestCount)

        service.getEpssScores(listOf("CVE-2022-22965", "CVE-2021-44228"))
        assertEquals(1, requestCount)
    }

    @Test
    fun `should return empty map for empty CVE list`() = runTest {
        val mockEngine = MockEngine { _ ->
            fail("Should not make HTTP request for empty CVE list")
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val result = service.getEpssScores(emptyList())
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should return empty map on 429 rate limit`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = "Too Many Requests",
                status = HttpStatusCode.TooManyRequests,
                headers = headersOf(HttpHeaders.ContentType, "text/plain")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val result = service.getEpssScores(listOf("CVE-2021-44228"))
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should return empty map on other client errors`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = "Bad Request",
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "text/plain")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val result = service.getEpssScores(listOf("CVE-2021-44228"))
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should return empty map on server errors`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = "Internal Server Error",
                status = HttpStatusCode.InternalServerError,
                headers = headersOf(HttpHeaders.ContentType, "text/plain")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(Json { ignoreUnknownKeys = true })
            }
        }

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val result = service.getEpssScores(listOf("CVE-2021-44228"))
        assertTrue(result.isEmpty())
    }

    @Test
    fun `should batch requests when CVE parameter exceeds 2000 characters`() = runTest {
        var requestCount = 0
        val mockEngine = MockEngine { request ->
            requestCount++
            val cveParam = request.url.parameters["cve"] ?: ""
            assertTrue(cveParam.length <= 2000, "CVE parameter length ${cveParam.length} exceeds 2000 characters")

            val cves = cveParam.split(",")
            val data = cves.map {
                """
                {
                    "cve": "$it",
                    "epss": "0.001230000",
                    "percentile": "0.456780000",
                    "date": "2025-11-20"
                }
                """.trimIndent()
            }.joinToString(",")

            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": ${cves.size},
                        "data": [$data]
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

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val largeCveList = (1..150).map { "CVE-2023-${it.toString().padStart(5, '0')}" }
        val paramLength = largeCveList.joinToString(",").length
        assertTrue(paramLength > 2000, "Test setup: CVE list should exceed 2000 chars, got $paramLength")

        val result = service.getEpssScores(largeCveList)

        assertEquals(150, result.size)
        assertTrue(requestCount > 1, "Should have made multiple requests for batching")
    }

    @Test
    fun `should handle multiple CVEs and return as map`() = runTest {
        val mockEngine = MockEngine { _ ->
            respond(
                content = """
                    {
                        "status": "OK",
                        "status-code": 200,
                        "total": 3,
                        "data": [
                            {
                                "cve": "CVE-2021-44228",
                                "epss": "0.942510000",
                                "percentile": "0.999630000",
                                "date": "2025-11-20"
                            },
                            {
                                "cve": "CVE-2022-22965",
                                "epss": "0.943870000",
                                "percentile": "0.999930000",
                                "date": "2025-11-20"
                            },
                            {
                                "cve": "CVE-2023-12345",
                                "epss": "0.001230000",
                                "percentile": "0.456780000",
                                "date": "2025-11-20"
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

        val epssClient = EpssClient(httpClient)
        val cache = InMemoryCache<String, Map<String, EpssScore>>()
        val service = CachedEpssService(epssClient, cache)

        val result = service.getEpssScores(listOf("CVE-2021-44228", "CVE-2022-22965", "CVE-2023-12345"))

        assertEquals(3, result.size)
        assertNotNull(result["CVE-2021-44228"])
        assertNotNull(result["CVE-2022-22965"])
        assertNotNull(result["CVE-2023-12345"])

        assertEquals("0.942510000", result["CVE-2021-44228"]?.epss)
        assertEquals("0.943870000", result["CVE-2022-22965"]?.epss)
        assertEquals("0.001230000", result["CVE-2023-12345"]?.epss)
    }
}

