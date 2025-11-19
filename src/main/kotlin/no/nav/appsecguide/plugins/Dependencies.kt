package no.nav.appsecguide.plugins

import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.util.*
import kotlinx.serialization.json.Json
import no.nav.appsecguide.infrastructure.auth.NaisTokenIntrospectionService
import no.nav.appsecguide.infrastructure.auth.TokenIntrospectionService
import no.nav.appsecguide.infrastructure.nais.NaisApiClient
import no.nav.appsecguide.infrastructure.nais.NaisApiService

class Dependencies(
    val tokenIntrospectionService: TokenIntrospectionService,
    val naisApiService: NaisApiService,
    @Suppress("unused")
    val httpClient: HttpClient
)

val DependenciesKey = AttributeKey<Dependencies>("Dependencies")

val DependenciesPlugin = createApplicationPlugin(name = "Dependencies") {
    val httpClient = HttpClient(CIO) {
        install(ContentNegotiation) {
            json(Json {
                prettyPrint = true
                isLenient = true
                ignoreUnknownKeys = true
            })
        }
    }

    val introspectionEndpoint = application.environment.config
        .propertyOrNull("nais.introspection.endpoint")?.getString()
        ?: System.getenv("NAIS_TOKEN_INTROSPECTION_ENDPOINT")
        ?: error("NAIS_TOKEN_INTROSPECTION_ENDPOINT not configured")

    val naisApiUrl = application.environment.config
        .propertyOrNull("nais.api.url")?.getString()
        ?: System.getenv("NAIS_API_URL")
        ?: error("NAIS_API_URL not configured")

    val naisApiToken = application.environment.config
        .propertyOrNull("nais.api.token")?.getString()
        ?: System.getenv("NAIS_API_TOKEN")
        ?: error("NAIS_API_TOKEN not configured")

    val tokenIntrospectionService = NaisTokenIntrospectionService(httpClient, introspectionEndpoint)
    val naisApiService = NaisApiClient(httpClient, naisApiUrl, naisApiToken)

    val dependencies = Dependencies(
        tokenIntrospectionService = tokenIntrospectionService,
        naisApiService = naisApiService,
        httpClient = httpClient
    )

    application.attributes.put(DependenciesKey, dependencies)
}

val Application.dependencies: Dependencies
    get() = attributes[DependenciesKey]

@Suppress("unused")
val ApplicationCall.dependencies: Dependencies
    get() = application.dependencies

