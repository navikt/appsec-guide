package no.nav.appsecguide.routes

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlinx.serialization.json.*
import kotlin.test.*
import no.nav.appsecguide.infrastructure.auth.MockTokenIntrospectionService
import no.nav.appsecguide.infrastructure.nais.MockNaisApiService
import no.nav.appsecguide.plugins.testModule

class NaisRoutesTest {

    @Test
    fun `should return team ingresses when team exists and authenticated`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123"),
                naisApiService = MockNaisApiService(shouldSucceed = true)
            )
        }
        val response = client.get("/nais/teams/appsec/ingresses") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.OK, response.status)

        val json = Json.parseToJsonElement(response.bodyAsText()).jsonObject
        assertNotNull(json["data"])
    }

    @Test
    fun `should return unauthorized when no token provided`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/nais/teams/appsec/ingresses")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `should return bad request when teamSlug is missing`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123")
            )
        }
        val response = client.get("/nais/teams//ingresses") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.NotFound, response.status)
    }

    @Test
    fun `should return error when GraphQL fails`() = testApplication {
        application {
            testModule(
                tokenIntrospectionService = MockTokenIntrospectionService(shouldSucceed = true, navIdent = "user123"),
                naisApiService = MockNaisApiService(shouldSucceed = false)
            )
        }
        val response = client.get("/nais/teams/appsec/ingresses") {
            bearerAuth("valid-token")
        }
        assertEquals(HttpStatusCode.BadGateway, response.status)
    }
}

