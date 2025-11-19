package no.nav.appsecguide.plugins

import io.ktor.server.application.*
import io.ktor.server.auth.*
import kotlinx.serialization.json.jsonPrimitive
import no.nav.appsecguide.infrastructure.auth.TokenIntrospectionService
import org.slf4j.LoggerFactory

data class TokenPrincipal(
    val navIdent: String,
    val claims: Map<String, String>
)

fun Application.configureAuthentication(tokenIntrospectionService: TokenIntrospectionService) {
    val logger = LoggerFactory.getLogger("TokenIntrospectionService")

    install(Authentication) {
        bearer("auth-bearer") {
            authenticate { credential ->
                try {
                    val introspectionResult = tokenIntrospectionService.introspect(credential.token)

                    if (!introspectionResult.active) {
                        return@authenticate null
                    }

                    val navIdent = introspectionResult.claims["NAVident"]?.jsonPrimitive?.content

                    if (navIdent != null) {
                        val claimsMap = introspectionResult.claims.mapValues {
                            it.value.jsonPrimitive.content
                        }
                        TokenPrincipal(navIdent, claimsMap)
                    } else {
                        null
                    }
                } catch (e: Exception) {
                    logger.error("Token introspection failed", e)
                    null
                }
            }
        }
    }
}

