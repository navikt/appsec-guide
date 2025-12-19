package no.nav.tpt.infrastructure.nvd

import io.ktor.client.*
import io.ktor.client.engine.mock.*
import io.ktor.http.*
import java.time.LocalDateTime

/**
 * Mock NVD repository for testing
 */
class MockNvdRepository : NvdRepository {
    private val cves = mutableMapOf<String, NvdCveData>()

    override suspend fun getCveData(cveId: String): NvdCveData? = cves[cveId]

    override suspend fun upsertCve(cve: NvdCveData) {
        cves[cve.cveId] = cve
    }

    override suspend fun upsertCves(cves: List<NvdCveData>) {
        cves.forEach { upsertCve(it) }
    }

    override suspend fun getLastModifiedDate(): LocalDateTime? =
        cves.values.maxByOrNull { it.lastModifiedDate }?.lastModifiedDate

    override suspend fun getCvesInKev(): List<NvdCveData> =
        cves.values.filter { it.cisaExploitAdd != null }

    fun clear() = cves.clear()

    fun count(): Int = cves.size
}

/**
 * Creates a mock NVD client for testing - returns empty responses
 */
private fun createMockNvdClient(): NvdClient {
    val mockHttpClient = HttpClient(MockEngine) {
        engine {
            addHandler { _ ->
                respond(
                    content = """{"vulnerabilities":[],"totalResults":0,"resultsPerPage":0,"startIndex":0,"format":"NVD_CVE","version":"2.0","timestamp":"2024-01-01T00:00:00.000"}""",
                    status = HttpStatusCode.OK,
                    headers = headersOf(HttpHeaders.ContentType, "application/json")
                )
            }
        }
    }
    return NvdClient(mockHttpClient, null)
}

/**
 * Mock NVD sync service for testing - extends real NvdSyncService but uses mock implementations
 */
class MockNvdSyncService : NvdSyncService(
    nvdClient = createMockNvdClient(),
    repository = MockNvdRepository()
)

