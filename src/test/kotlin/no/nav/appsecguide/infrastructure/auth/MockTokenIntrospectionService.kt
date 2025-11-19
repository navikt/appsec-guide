package no.nav.appsecguide.infrastructure.auth

import kotlinx.serialization.json.JsonPrimitive

class MockTokenIntrospectionService(
    private val shouldSucceed: Boolean = false,
    private val navIdent: String? = null
) : TokenIntrospectionService {
    override suspend fun introspect(token: String): IntrospectionResponse {
        if (!shouldSucceed) {
            return IntrospectionResponse(active = false)
        }

        val claims = if (navIdent != null) {
            mapOf("NAVident" to JsonPrimitive(navIdent))
        } else {
            emptyMap()
        }

        return IntrospectionResponse(active = true, claims = claims)
    }
}

