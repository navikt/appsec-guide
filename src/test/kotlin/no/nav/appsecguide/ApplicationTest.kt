package no.nav.appsecguide

import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.server.testing.*
import kotlin.test.*
import no.nav.appsecguide.plugins.testModule

class ApplicationTest {
    @Test
    fun `should return isready when calling isready endpoint`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/isready")
        assertEquals(HttpStatusCode.OK, response.status)
    }

    @Test
    fun `should return isalive when calling isalive endpoint`() = testApplication {
        application {
            testModule()
        }
        val response = client.get("/isalive")
        assertEquals(HttpStatusCode.OK, response.status)
    }
}

