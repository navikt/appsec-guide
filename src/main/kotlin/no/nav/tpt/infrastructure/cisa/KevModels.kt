package no.nav.tpt.infrastructure.cisa

import kotlinx.serialization.Serializable

@Serializable
data class KevCatalog(
    val title: String,
    val catalogVersion: String,
    val dateReleased: String,
    val count: Int,
    val vulnerabilities: List<KevVulnerability>
)

@Serializable
data class KevVulnerability(
    val cveID: String,
    val vendorProject: String,
    val product: String,
    val vulnerabilityName: String,
    val dateAdded: String,
    val shortDescription: String,
    val requiredAction: String,
    val dueDate: String,
    val knownRansomwareCampaignUse: String,
    val notes: String,
    val cwes: List<String>
)
