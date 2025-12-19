package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlin.test.*

class NvdClientTest {

    private val json = Json {
        ignoreUnknownKeys = true
        prettyPrint = true
    }

    @Test
    fun `should successfully fetch CVE by ID`() = runTest {
        val cve = NvdTestDataBuilder.buildCriticalKevCve()
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = listOf(NvdTestDataBuilder.buildVulnerabilityItem(cve))
        )

        val mockEngine = MockEngine { request ->
            assertEquals("https://services.nvd.nist.gov/rest/json/cves/2.0", request.url.toString().substringBefore('?'))
            assertTrue(request.url.parameters.contains("cveId"))
            assertEquals("CVE-2024-9999", request.url.parameters["cveId"])

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val result = nvdClient.getCveByCveId("CVE-2024-9999")

        assertNotNull(result)
        assertEquals("CVE-2024-9999", result.id)
        assertEquals("2024-01-20", result.cisaExploitAdd)
        assertEquals("2024-02-10", result.cisaActionDue)
    }

    @Test
    fun `should return null when CVE not found`() = runTest {
        val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())

        val mockEngine = MockEngine {
            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val result = nvdClient.getCveByCveId("CVE-9999-NOTFOUND")

        assertNull(result)
    }

    @Test
    fun `should fetch CVEs by modified date range`() = runTest {
        val cves = listOf(
            NvdTestDataBuilder.buildCriticalKevCve(),
            NvdTestDataBuilder.buildHighSeverityWithExploit()
        )
        val response = NvdTestDataBuilder.buildNvdResponse(
            vulnerabilities = cves.map { NvdTestDataBuilder.buildVulnerabilityItem(it) },
            totalResults = 2
        )

        val mockEngine = MockEngine { request ->
            assertTrue(request.url.parameters.contains("lastModStartDate"))
            assertTrue(request.url.parameters.contains("lastModEndDate"))

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, null)
        val result = nvdClient.getCvesByModifiedDate(
            lastModStartDate = java.time.LocalDateTime.now().minusDays(7),
            lastModEndDate = java.time.LocalDateTime.now()
        )

        assertEquals(2, result.totalResults)
        assertEquals(2, result.vulnerabilities.size)
    }

    @Test
    fun `should include API key header when provided`() = runTest {
        val response = NvdTestDataBuilder.buildNvdResponse(vulnerabilities = emptyList())

        val mockEngine = MockEngine { request ->
            assertEquals("test-api-key", request.headers["apiKey"])

            respond(
                content = json.encodeToString(response),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json")
            )
        }

        val httpClient = HttpClient(mockEngine) {
            install(ContentNegotiation) {
                json(json)
            }
        }

        val nvdClient = NvdClient(httpClient, "test-api-key")
        nvdClient.getCveByCveId("CVE-2024-1234")
    }

    @Test
    fun `should correctly map CVE with CISA KEV data`() = runTest {
        val cve = NvdTestDataBuilder.buildCriticalKevCve()
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertEquals("CVE-2024-9999", result.cveId)
        assertNotNull(result.cisaExploitAdd)
        assertEquals(java.time.LocalDate.parse("2024-01-20"), result.cisaExploitAdd)
        assertEquals(java.time.LocalDate.parse("2024-02-10"), result.cisaActionDue)
        assertEquals("Apply updates per vendor instructions", result.cisaRequiredAction)
        assertEquals("Critical Authentication Bypass", result.cisaVulnerabilityName)
    }

    @Test
    fun `should prioritize CVSS v3 1 over other versions`() = runTest {
        val cve = NvdTestDataBuilder.buildCveWithMultipleCvssVersions()
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertEquals(7.8, result.cvssV31Score)
        assertEquals("HIGH", result.cvssV31Severity)
        assertEquals(7.5, result.cvssV30Score)
        assertEquals("HIGH", result.cvssV30Severity)
        assertEquals(6.8, result.cvssV2Score)
        assertEquals("MEDIUM", result.cvssV2Severity) // Calculated from score: 6.8 < 7.0
    }

    @Test
    fun `should extract CWE IDs from weaknesses`() = runTest {
        val cve = NvdTestDataBuilder.buildCriticalKevCve()
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertEquals(listOf("CWE-287"), result.cweIds)
    }

    @Test
    fun `should detect exploit reference tags`() = runTest {
        val cve = NvdTestDataBuilder.buildHighSeverityWithExploit()
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertTrue(result.hasExploitReference)
        assertFalse(result.hasPatchReference)
    }

    @Test
    fun `should detect patch reference tags`() = runTest {
        val cve = NvdTestDataBuilder.buildMediumSeverityWithPatch()
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertFalse(result.hasExploitReference)
        assertTrue(result.hasPatchReference)
    }

    @Test
    fun `should handle CVE with no CVSS scores`() = runTest {
        val cve = NvdTestDataBuilder.buildRejectedCve()
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertNull(result.cvssV31Score)
        assertNull(result.cvssV30Score)
        assertNull(result.cvssV2Score)
    }

    @Test
    fun `should extract English description`() = runTest {
        val cve = NvdTestDataBuilder.buildCveItem(
            descriptions = listOf(
                CveDescription("es", "Una vulnerabilidad de desbordamiento de búfer existe."),
                CveDescription("en", "A buffer overflow vulnerability exists."),
                CveDescription("fr", "Une vulnérabilité de dépassement de tampon existe.")
            )
        )
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertEquals("A buffer overflow vulnerability exists.", result.description)
    }

    @Test
    fun `should calculate days old correctly`() = runTest {
        val publishedDate = java.time.LocalDateTime.now().minusDays(30)
        val cve = NvdTestDataBuilder.buildCveItem(
            published = "${publishedDate}Z"
        )
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertTrue(result.daysOld >= 29 && result.daysOld <= 31) // Allow for timing variations
    }

    @Test
    fun `should handle Primary vs Secondary CVSS scores`() = runTest {
        val cve = NvdTestDataBuilder.buildCveItem(
            cvssV31 = CvssMetricV31(
                source = "secondary@example.com",
                type = "Secondary",
                cvssData = CvssDataV31("3.1", "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L", 5.0, "MEDIUM")
            )
        )
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        // Should use Secondary score since no Primary is available
        assertEquals(5.0, result.cvssV31Score)
        assertEquals("MEDIUM", result.cvssV31Severity)
    }

    @Test
    fun `should extract all reference URLs`() = runTest {
        val cve = NvdTestDataBuilder.buildCveItem(
            references = listOf(
                CveReference("https://example.com/advisory1", "vendor@example.com", listOf("Vendor Advisory")),
                CveReference("https://example.com/advisory2", "vendor@example.com", listOf("Patch")),
                CveReference("https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-1234", "mitre", null)
            )
        )
        val nvdClient = NvdClient(HttpClient(), null)

        val result = nvdClient.mapToNvdCveData(cve)

        assertEquals(3, result.references.size)
        assertTrue(result.references.contains("https://example.com/advisory1"))
        assertTrue(result.references.contains("https://example.com/advisory2"))
    }
}

