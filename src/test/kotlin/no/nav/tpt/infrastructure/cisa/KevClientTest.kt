package no.nav.tpt.infrastructure.cisa

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlin.test.Test
import kotlin.test.assertEquals

class KevClientTest {

    @Test
    fun `should fetch KEV catalog from CISA`() = runTest {
        val mockEngine = MockEngine { _ ->
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
                                "shortDescription": "Test description",
                                "requiredAction": "Test action",
                                "dueDate": "2025-12-10",
                                "knownRansomwareCampaignUse": "Unknown",
                                "notes": "Test notes",
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
        val catalog = kevClient.getKevCatalog()

        assertEquals("CISA Catalog of Known Exploited Vulnerabilities", catalog.title)
        assertEquals("2025.11.19", catalog.catalogVersion)
        assertEquals(1, catalog.count)
        assertEquals(1, catalog.vulnerabilities.size)
        assertEquals("CVE-2025-13223", catalog.vulnerabilities[0].cveID)
    }
}

