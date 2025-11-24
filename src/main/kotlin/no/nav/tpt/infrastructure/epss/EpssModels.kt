package no.nav.tpt.infrastructure.epss

import kotlinx.serialization.Serializable

@Serializable
data class EpssResponse(
    val status: String,
    val total: Int,
    val data: List<EpssScore>
)

@Serializable
data class EpssScore(
    val cve: String,
    val epss: String,
    val percentile: String,
    val date: String
)

