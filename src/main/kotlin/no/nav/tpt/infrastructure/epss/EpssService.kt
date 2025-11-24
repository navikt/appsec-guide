package no.nav.tpt.infrastructure.epss

interface EpssService {
    suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore>
}

