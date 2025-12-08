package no.nav.tpt.domain.risk

interface RiskScorer {
    fun calculateRiskScore(context: VulnerabilityRiskContext): Double
}

