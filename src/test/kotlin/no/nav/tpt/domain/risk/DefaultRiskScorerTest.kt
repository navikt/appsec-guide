package no.nav.tpt.domain.risk

import org.junit.Assert.assertFalse
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DefaultRiskScorerTest {

    private val riskScorer = DefaultRiskScorer()

    @Test
    fun `should apply 0_3 multiplier to suppressed vulnerabilities`() {
        val suppressedScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.9",
                suppressed = true,
                environment = null,
                buildDate = null
            )
        ).score

        val normalScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.9",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(0.3, suppressedScore / normalScore, 0.001)
        assertTrue(suppressedScore > 0.0)
    }

    @Test
    fun `should calculate higher risk for critical vulnerability with external ingress`() {
        val criticalExternal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val mediumExternal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(criticalExternal > mediumExternal)
    }

    @Test
    fun `should apply external ingress multiplier correctly`() {
        val baseScore = 100.0
        val externalMultiplier = 2.0

        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(baseScore * externalMultiplier, score, 0.001)
    }

    @Test
    fun `should apply KEV multiplier correctly`() {
        val withKev = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = true,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val withoutKev = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(1.5, withKev / withoutKev, 0.001)
    }

    @Test
    fun `should apply EPSS multiplier correctly`() {
        val highEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = "0.8",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val noEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(highEpss > noEpss)
    }

    @Test
    fun `should multiply all factors together`() {
        val baseScore = 100.0
        val externalMultiplier = 2.0
        val kevMultiplier = 1.5
        val epssMultiplier = 1.5

        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.8",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val expected = baseScore * externalMultiplier * kevMultiplier * epssMultiplier
        assertEquals(expected, score, 0.001)
    }

    @Test
    fun `should reduce score for internal ingress compared to external`() {
        val external = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val internal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(external > internal)
    }

    @Test
    fun `should reduce score for authenticated compared to external`() {
        val external = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val authenticated = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("AUTHENTICATED"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(external > authenticated)
    }

    @Test
    fun `should not reduce score for low EPSS values`() {
        val lowEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "0.05",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val noEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(lowEpss, noEpss)
    }

    @Test
    fun `should reduce score for no ingress`() {
        val withIngress = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val noIngress = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(noIngress < withIngress)
    }

    @Test
    fun `should handle invalid EPSS score gracefully`() {
        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = "invalid",
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertTrue(score > 0.0)
    }

    @Test
    fun `should prioritize external over internal when multiple ingress types exist`() {
        val mixed = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL", "EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val externalOnly = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(externalOnly, mixed)
    }

    @Test
    fun `should apply 1_1 multiplier for prod-gcp environment`() {
        val prodScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-gcp",
                buildDate = null
            )
        ).score

        val devScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null
            )
        ).score

        assertEquals(1.1, prodScore / devScore, 0.001)
    }

    @Test
    fun `should apply 1_1 multiplier for prod-fss environment`() {
        val prodScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "prod-fss",
                buildDate = null
            )
        ).score

        val devScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-fss",
                buildDate = null
            )
        ).score

        assertEquals(1.1, prodScore / devScore, 0.001)
    }

    @Test
    fun `should not apply multiplier for dev environments`() {
        val devGcpScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp",
                buildDate = null
            )
        ).score

        val noEnvScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(devGcpScore, noEnvScore)
    }

    @Test
    fun `should not apply multiplier for null environment`() {
        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        val baseScore = 70.0
        val externalMultiplier = 2.0
        val expected = baseScore * externalMultiplier

        assertEquals(expected, score, 0.001)
    }

    @Test
    fun `should apply 1_1 multiplier for old builds`() {
        val oldBuildDate = java.time.LocalDate.now().minusDays(100)

        val oldBuildScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = oldBuildDate
            )
        ).score

        val recentBuildScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = java.time.LocalDate.now().minusDays(30)
            )
        ).score

        assertEquals(1.1, oldBuildScore / recentBuildScore, 0.001)
    }

    @Test
    fun `should not apply multiplier for recent builds`() {
        val recentBuildScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = java.time.LocalDate.now().minusDays(30)
            )
        ).score

        val noBuildDateScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = null
            )
        ).score

        assertEquals(recentBuildScore, noBuildDateScore)
    }

    @Test
    fun `should apply multiplier at 90 day threshold`() {
        val atThreshold = java.time.LocalDate.now().minusDays(91)

        val score = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = atThreshold
            )
        ).score

        val baseScore = 40.0
        val internalMultiplier = 1.0
        val oldBuildMultiplier = 1.1
        val expected = baseScore * internalMultiplier * oldBuildMultiplier

        assertEquals(expected, score, 0.001)
    }

    @Test
    fun `should include build age in multipliers when old`() {
        val oldBuildDate = java.time.LocalDate.now().minusDays(120)

        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = oldBuildDate
            )
        )

        assertTrue(result.multipliers.containsKey("old_build"))
        assertTrue(result.multipliers.containsKey("old_build_days"))
        assertEquals(1.1, result.multipliers["old_build"])
        assertEquals(120.0, result.multipliers["old_build_days"])
    }

    @Test
    fun `should not include build age in multipliers when recent`() {
        val recentBuildDate = java.time.LocalDate.now().minusDays(30)

        val result = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null,
                buildDate = recentBuildDate
            )
        )

        assertFalse(result.multipliers.containsKey("old_build"))
        assertFalse(result.multipliers.containsKey("old_build_days"))
    }
}

