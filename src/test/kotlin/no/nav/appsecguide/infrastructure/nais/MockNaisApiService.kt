package no.nav.appsecguide.infrastructure.nais

class MockNaisApiService(
    private val shouldSucceed: Boolean = true,
    private val mockResponse: TeamIngressTypesResponse? = null
) : NaisApiService {

    override suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse {
        if (!shouldSucceed) {
            return TeamIngressTypesResponse(
                errors = listOf(
                    TeamIngressTypesResponse.GraphQLError(
                        message = "Mock error",
                        path = listOf("team")
                    )
                )
            )
        }

        return mockResponse ?: TeamIngressTypesResponse(
            data = TeamIngressTypesResponse.Data(
                team = TeamIngressTypesResponse.Team(
                    applications = TeamIngressTypesResponse.Applications(
                        pageInfo = TeamIngressTypesResponse.PageInfo(
                            hasNextPage = false,
                            endCursor = null
                        ),
                        edges = listOf(
                            TeamIngressTypesResponse.Edge(
                                node = TeamIngressTypesResponse.Application(
                                    name = "test-app",
                                    ingresses = listOf(
                                        TeamIngressTypesResponse.Ingress(type = "internal")
                                    )
                                )
                            )
                        )
                    )
                )
            )
        )
    }
}

