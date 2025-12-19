package no.nav.tpt.infrastructure.nvd

import java.time.LocalDateTime

interface NvdRepository {
    suspend fun getCveData(cveId: String): NvdCveData?
    suspend fun upsertCve(cve: NvdCveData)
    suspend fun upsertCves(cves: List<NvdCveData>)
    suspend fun getLastModifiedDate(): LocalDateTime?
    suspend fun getCvesInKev(): List<NvdCveData>
}

