package no.nav.appsecguide.infrastructure.epss

class MockEpssService(
    private val mockScores: Map<String, EpssScore> = emptyMap()
) : EpssService {
    override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> {
        return mockScores.filterKeys { it in cveIds }
    }
}

