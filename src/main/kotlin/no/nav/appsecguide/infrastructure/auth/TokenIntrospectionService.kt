package no.nav.appsecguide.infrastructure.auth

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.request.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonElement

@Suppress("PropertyName")
@Serializable
data class IntrospectionRequest(
    val identity_provider: String,
    val token: String
)

@Serializable
data class IntrospectionResponse(
    val active: Boolean,
    val claims: Map<String, JsonElement> = emptyMap()
)

interface TokenIntrospectionService {
    suspend fun introspect(token: String): IntrospectionResponse
}

class NaisTokenIntrospectionService(
    private val httpClient: HttpClient,
    private val introspectionEndpoint: String
) : TokenIntrospectionService {

    override suspend fun introspect(token: String): IntrospectionResponse {
        val response = httpClient.post(introspectionEndpoint) {
            contentType(ContentType.Application.Json)
            setBody(IntrospectionRequest(
                identity_provider = "azuread",
                token = token
            ))
        }

        return response.body()
    }
}

