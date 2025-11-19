package no.nav.appsecguide

import io.ktor.serialization.kotlinx.json.json
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.routing.*
import io.ktor.server.plugins.contentnegotiation.ContentNegotiation as ServerContentNegotiation
import kotlinx.serialization.json.Json
import no.nav.appsecguide.plugins.DependenciesPlugin
import no.nav.appsecguide.plugins.configureAuthentication
import no.nav.appsecguide.plugins.dependencies
import no.nav.appsecguide.routes.healthRoutes
import no.nav.appsecguide.routes.naisRoutes
import no.nav.appsecguide.routes.userRoutes

fun main() {
    embeddedServer(Netty, port = 8080, host = "0.0.0.0", module = Application::module)
        .start(wait = true)
}

fun Application.module() {
    install(DependenciesPlugin)

    install(ServerContentNegotiation) {
        json(Json {
            prettyPrint = true
            isLenient = true
        })
    }

    configureAuthentication(dependencies.tokenIntrospectionService)

    routing {
        healthRoutes()
        userRoutes()
        naisRoutes()
    }
}

