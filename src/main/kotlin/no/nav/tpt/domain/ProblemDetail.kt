package no.nav.tpt.domain

import kotlinx.serialization.Serializable

@Serializable
data class ProblemDetail(
    val type: String,
    val title: String,
    val status: Int,
    val detail: String? = null,
    val instance: String? = null
)

