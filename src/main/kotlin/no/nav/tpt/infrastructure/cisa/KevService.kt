package no.nav.tpt.infrastructure.cisa

interface KevService {
    suspend fun getKevCatalog(): KevCatalog
}

