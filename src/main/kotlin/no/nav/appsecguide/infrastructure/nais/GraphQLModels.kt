package no.nav.appsecguide.infrastructure.nais

import kotlinx.serialization.Serializable

@Serializable
data class TeamIngressTypesRequest(
    val query: String,
    val variables: Variables
) {
    @Serializable
    data class Variables(
        val teamSlug: String,
        val appFirst: Int = 100,
        val appAfter: String? = null
    )
}

@Serializable
data class TeamIngressTypesResponse(
    val data: Data? = null,
    val errors: List<GraphQLError>? = null
) {
    @Serializable
    data class Data(
        val team: Team?
    )

    @Serializable
    data class Team(
        val applications: Applications
    )

    @Serializable
    data class Applications(
        val pageInfo: PageInfo,
        val edges: List<Edge>
    )

    @Serializable
    data class PageInfo(
        val hasNextPage: Boolean,
        val endCursor: String?
    )

    @Serializable
    data class Edge(
        val node: Application
    )

    @Serializable
    data class Application(
        val name: String,
        val ingresses: List<Ingress>
    )

    @Serializable
    data class Ingress(
        val type: String
    )

    @Serializable
    data class GraphQLError(
        val message: String,
        val path: List<String>? = null
    )
}

