package no.nav.appsecguide.routes

import io.ktor.server.auth.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.*
import kotlinx.serialization.Serializable
import no.nav.appsecguide.plugins.TokenPrincipal

@Serializable
data class UserInfoResponse(
    val navIdent: String,
    val preferredUsername: String?
)

fun Route.userRoutes() {
    authenticate("auth-bearer") {
        get("/me") {
            val principal = call.principal<TokenPrincipal>()
            val navIdent = principal?.navIdent

            if (navIdent != null) {
                call.respond(HttpStatusCode.OK, UserInfoResponse(navIdent, principal.preferredUsername))
            } else {
                call.respondUnauthorized("NAVident claim not found in token")
            }
        }
    }
}

