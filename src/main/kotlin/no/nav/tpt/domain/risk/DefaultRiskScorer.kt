package no.nav.tpt.domain.risk

class DefaultRiskScorer : RiskScorer {

    override fun calculateRiskScore(context: VulnerabilityRiskContext): Double {
        val baseScore = getBaseSeverityScore(context.severity)
        val exposureMultiplier = getExposureMultiplier(context.ingressTypes)
        val kevMultiplier = getKevMultiplier(context.hasKevEntry)
        val epssMultiplier = getEpssMultiplier(context.epssScore)
        val suppressedMultiplier = if (context.suppressed) 0.3 else 1.0
        val environmentMultiplier = getEnvironmentMultiplier(context.environment)

        return baseScore * exposureMultiplier * kevMultiplier * epssMultiplier * suppressedMultiplier * environmentMultiplier
    }

    private fun getBaseSeverityScore(severity: String): Double {
        return when (severity.uppercase()) {
            "CRITICAL" -> 100.0
            "HIGH" -> 70.0
            "MEDIUM" -> 40.0
            "LOW" -> 20.0
            else -> 10.0
        }
    }

    private fun getExposureMultiplier(ingressTypes: List<String>): Double {
        if (ingressTypes.isEmpty()) {
            return 0.5
        }

        val hasExternal = ingressTypes.any { it.equals("EXTERNAL", ignoreCase = true) }
        val hasAuthenticated = ingressTypes.any { it.equals("AUTHENTICATED", ignoreCase = true) }
        val hasInternal = ingressTypes.any { it.equals("INTERNAL", ignoreCase = true) }

        return when {
            hasExternal -> 2.0
            hasAuthenticated -> 1.5
            hasInternal -> 1.0
            else -> 0.5
        }
    }

    private fun getKevMultiplier(hasKevEntry: Boolean): Double {
        return if (hasKevEntry) 1.5 else 1.0
    }

    private fun getEpssMultiplier(epssScore: String?): Double {
        if (epssScore == null) {
            return 1.0
        }

        return try {
            val score = epssScore.toDouble()
            when {
                score >= 0.7 -> 1.5
                score >= 0.5 -> 1.3
                score >= 0.3 -> 1.2
                score >= 0.1 -> 1.1
                else -> 1.0
            }
        } catch (_: NumberFormatException) {
            1.0
        }
    }

    private fun getEnvironmentMultiplier(environment: String?): Double {
        if (environment == null) {
            return 1.0
        }

        return when {
            environment.startsWith("prod-", ignoreCase = true) -> 1.1
            else -> 1.0
        }
    }
}

