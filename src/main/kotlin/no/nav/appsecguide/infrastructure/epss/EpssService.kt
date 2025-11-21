package no.nav.appsecguide.infrastructure.epss

interface EpssService {
    suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore>
}

