package no.nav.appsecguide.routes

import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.http.*

fun Route.healthRoutes() {
    get("/isready") {
        call.respondText("KIROV REPORTING", ContentType.Text.Plain)
    }
    get("/isalive") {
        call.respondText("A-OK", ContentType.Text.Plain)
    }
}

