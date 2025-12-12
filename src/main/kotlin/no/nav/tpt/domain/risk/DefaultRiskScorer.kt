package no.nav.tpt.domain.risk

class DefaultRiskScorer : RiskScorer {

    companion object {
        // Base severity scores
        const val CRITICAL_BASE_SCORE = 100.0
        const val HIGH_BASE_SCORE = 70.0
        const val MEDIUM_BASE_SCORE = 40.0
        const val LOW_BASE_SCORE = 20.0
        const val UNKNOWN_BASE_SCORE = 10.0

        // Exposure multipliers
        const val EXTERNAL_EXPOSURE_MULTIPLIER = 2.0
        const val AUTHENTICATED_EXPOSURE_MULTIPLIER = 1.5
        const val INTERNAL_EXPOSURE_MULTIPLIER = 1.0
        const val NO_INGRESS_MULTIPLIER = 0.5

        // KEV multipliers
        const val KEV_LISTED_MULTIPLIER = 1.5
        const val NO_KEV_MULTIPLIER = 1.0

        // EPSS multipliers
        const val EPSS_VERY_HIGH_MULTIPLIER = 1.5
        const val EPSS_HIGH_MULTIPLIER = 1.3
        const val EPSS_MEDIUM_MULTIPLIER = 1.2
        const val EPSS_LOW_MULTIPLIER = 1.1
        const val EPSS_NONE_MULTIPLIER = 1.0

        // Suppression multiplier
        const val SUPPRESSED_MULTIPLIER = 0.3

        // Environment multipliers
        const val PRODUCTION_ENVIRONMENT_MULTIPLIER = 1.1
        const val NON_PRODUCTION_MULTIPLIER = 1.0

        // Build time multipliers
        const val OLD_BUILD_MULTIPLIER = 1.1
        const val RECENT_BUILD_MULTIPLIER = 1.0
        const val OLD_BUILD_THRESHOLD_DAYS = 90
    }

    override fun calculateRiskScore(context: VulnerabilityRiskContext): RiskScoreResult {
        val baseScore = getBaseSeverityScore(context.severity)
        val exposureMultiplier = getExposureMultiplier(context.ingressTypes)
        val kevMultiplier = getKevMultiplier(context.hasKevEntry)
        val epssMultiplier = getEpssMultiplier(context.epssScore)
        val suppressedMultiplier = if (context.suppressed) SUPPRESSED_MULTIPLIER else 1.0
        val environmentMultiplier = getEnvironmentMultiplier(context.environment)
        val buildTimeMultiplier = getBuildTimeMultiplier(context.buildDate)

        val finalScore = baseScore * exposureMultiplier * kevMultiplier * epssMultiplier * suppressedMultiplier * environmentMultiplier * buildTimeMultiplier

        val multipliers = buildMultipliersMap(
            severity = context.severity,
            baseScore = baseScore,
            exposureMultiplier = exposureMultiplier,
            hasKevEntry = context.hasKevEntry,
            kevMultiplier = kevMultiplier,
            epssScore = context.epssScore,
            epssMultiplier = epssMultiplier,
            suppressed = context.suppressed,
            suppressedMultiplier = suppressedMultiplier,
            environment = context.environment,
            environmentMultiplier = environmentMultiplier,
            buildDate = context.buildDate,
            buildTimeMultiplier = buildTimeMultiplier
        )

        return RiskScoreResult(score = finalScore, multipliers = multipliers)
    }

    private fun buildMultipliersMap(
        severity: String,
        baseScore: Double,
        exposureMultiplier: Double,
        hasKevEntry: Boolean,
        kevMultiplier: Double,
        epssScore: String?,
        epssMultiplier: Double,
        suppressed: Boolean,
        suppressedMultiplier: Double,
        environment: String?,
        environmentMultiplier: Double,
        buildDate: java.time.LocalDate?,
        buildTimeMultiplier: Double
    ): Map<String, Double> {
        val multipliers = mutableMapOf<String, Double>()

        multipliers["base_${severity.lowercase()}"] = baseScore

        if (exposureMultiplier != 1.0) {
            multipliers["exposure"] = exposureMultiplier
        }

        if (kevMultiplier != 1.0) {
            multipliers["kev"] = kevMultiplier
        }

        epssScore?.let {
            try {
                val score = it.toDouble()
                if (score >= 0.1 && epssMultiplier != 1.0) {
                    multipliers["epss"] = epssMultiplier
                }
            } catch (_: NumberFormatException) {}
        }

        if (suppressed) {
            multipliers["suppressed"] = suppressedMultiplier
        }

        if (environmentMultiplier != 1.0) {
            multipliers["production"] = environmentMultiplier
        }

        buildDate?.let {
            val daysOld = java.time.temporal.ChronoUnit.DAYS.between(it, java.time.LocalDate.now())
            if (daysOld > OLD_BUILD_THRESHOLD_DAYS && buildTimeMultiplier != 1.0) {
                multipliers["old_build_days"] = daysOld.toDouble()
                multipliers["old_build"] = buildTimeMultiplier
            }
        }

        return multipliers
    }

    private fun getBaseSeverityScore(severity: String): Double {
        return when (severity.uppercase()) {
            "CRITICAL" -> CRITICAL_BASE_SCORE
            "HIGH" -> HIGH_BASE_SCORE
            "MEDIUM" -> MEDIUM_BASE_SCORE
            "LOW" -> LOW_BASE_SCORE
            else -> UNKNOWN_BASE_SCORE
        }
    }

    private fun getExposureMultiplier(ingressTypes: List<String>): Double {
        if (ingressTypes.isEmpty()) {
            return NO_INGRESS_MULTIPLIER
        }

        val hasExternal = ingressTypes.any { it.equals("EXTERNAL", ignoreCase = true) }
        val hasAuthenticated = ingressTypes.any { it.equals("AUTHENTICATED", ignoreCase = true) }
        val hasInternal = ingressTypes.any { it.equals("INTERNAL", ignoreCase = true) }

        return when {
            hasExternal -> EXTERNAL_EXPOSURE_MULTIPLIER
            hasAuthenticated -> AUTHENTICATED_EXPOSURE_MULTIPLIER
            hasInternal -> INTERNAL_EXPOSURE_MULTIPLIER
            else -> NO_INGRESS_MULTIPLIER
        }
    }

    private fun getKevMultiplier(hasKevEntry: Boolean): Double {
        return if (hasKevEntry) KEV_LISTED_MULTIPLIER else NO_KEV_MULTIPLIER
    }

    private fun getEpssMultiplier(epssScore: String?): Double {
        if (epssScore == null) {
            return EPSS_NONE_MULTIPLIER
        }

        return try {
            val score = epssScore.toDouble()
            when {
                score >= 0.7 -> EPSS_VERY_HIGH_MULTIPLIER
                score >= 0.5 -> EPSS_HIGH_MULTIPLIER
                score >= 0.3 -> EPSS_MEDIUM_MULTIPLIER
                score >= 0.1 -> EPSS_LOW_MULTIPLIER
                else -> EPSS_NONE_MULTIPLIER
            }
        } catch (_: NumberFormatException) {
            EPSS_NONE_MULTIPLIER
        }
    }

    private fun getEnvironmentMultiplier(environment: String?): Double {
        if (environment == null) {
            return NON_PRODUCTION_MULTIPLIER
        }

        return when {
            environment.startsWith("prod-", ignoreCase = true) -> PRODUCTION_ENVIRONMENT_MULTIPLIER
            else -> NON_PRODUCTION_MULTIPLIER
        }
    }

    private fun getBuildTimeMultiplier(buildDate: java.time.LocalDate?): Double {
        if (buildDate == null) {
            return RECENT_BUILD_MULTIPLIER
        }

        val daysOld = java.time.temporal.ChronoUnit.DAYS.between(buildDate, java.time.LocalDate.now())
        return if (daysOld > OLD_BUILD_THRESHOLD_DAYS) {
            OLD_BUILD_MULTIPLIER
        } else {
            RECENT_BUILD_MULTIPLIER
        }
    }
}

