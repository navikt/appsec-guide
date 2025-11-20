package no.nav.appsecguide.infrastructure.cisa

interface KevService {
    suspend fun getKevCatalog(): KevCatalog
}

