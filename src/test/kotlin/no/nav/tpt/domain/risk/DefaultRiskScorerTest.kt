package no.nav.tpt.domain.risk

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
                environment = null
            )
        )

        val normalScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = true,
                epssScore = "0.9",
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        val mediumExternal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        assertEquals(baseScore * externalMultiplier, score)
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
                environment = null
            )
        )

        val withoutKev = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        val noEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

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
                environment = null
            )
        )

        val internal = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        val authenticated = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("AUTHENTICATED"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        val noEpss = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        val noIngress = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = emptyList(),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

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
                environment = null
            )
        )

        val externalOnly = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = "prod-gcp"
            )
        )

        val devScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "HIGH",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-gcp"
            )
        )

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
                environment = "prod-fss"
            )
        )

        val devScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "MEDIUM",
                ingressTypes = listOf("INTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = "dev-fss"
            )
        )

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
                environment = "dev-gcp"
            )
        )

        val noEnvScore = riskScorer.calculateRiskScore(
            VulnerabilityRiskContext(
                severity = "CRITICAL",
                ingressTypes = listOf("EXTERNAL"),
                hasKevEntry = false,
                epssScore = null,
                suppressed = false,
                environment = null
            )
        )

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
                environment = null
            )
        )

        val baseScore = 70.0
        val externalMultiplier = 2.0
        val expected = baseScore * externalMultiplier

        assertEquals(expected, score)
    }
}

