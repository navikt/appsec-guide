package no.nav.tpt.domain.risk

data class RiskScoreResult(
    val score: Double,
    val multipliers: Map<String, Double>
)

