package no.nav.tpt.infrastructure.nvd

import kotlinx.coroutines.delay
import org.slf4j.LoggerFactory
import java.time.LocalDateTime

open class NvdSyncService(
    private val nvdClient: NvdClient,
    private val repository: NvdRepository
) {
    private val logger = LoggerFactory.getLogger(NvdSyncService::class.java)

    suspend fun performInitialSync() {
        logger.info("Starting initial NVD sync - this will take approximately 12-15 hours")

        // Sync year by year from 2002 to present
        val startYear = 2002
        val currentYear = LocalDateTime.now().year

        for (year in startYear..currentYear) {
            val startDate = LocalDateTime.of(year, 1, 1, 0, 0)
            val endDate = LocalDateTime.of(year, 12, 31, 23, 59)

            logger.info("Syncing CVEs from year $year")
            syncDateRange(startDate, endDate)

            // Respect rate limits: 6 seconds between requests (safe for both free and paid tiers)
            delay(6000)
        }

        logger.info("Initial NVD sync completed successfully")
    }

    suspend fun performIncrementalSync() {
        val lastModified = repository.getLastModifiedDate()
            ?: LocalDateTime.now().minusDays(7) // Default: last 7 days if no data

        val now = LocalDateTime.now()

        logger.info("Performing incremental sync for CVEs modified between $lastModified and $now")
        val cvesProcessed = syncDateRange(lastModified, now)
        logger.info("Incremental sync completed. Processed $cvesProcessed CVEs")
    }

    suspend fun syncDateRange(startDate: LocalDateTime, endDate: LocalDateTime): Int {
        var startIndex = 0
        val resultsPerPage = 2000 // Max allowed by NVD API
        var totalProcessed = 0

        do {
            try {
                val response = nvdClient.getCvesByModifiedDate(
                    lastModStartDate = startDate,
                    lastModEndDate = endDate,
                    startIndex = startIndex,
                    resultsPerPage = resultsPerPage
                )

                if (response.vulnerabilities.isNotEmpty()) {
                    val cveDataList = response.vulnerabilities
                        .map { it.cve }
                        .map { nvdClient.mapToNvdCveData(it) }

                    repository.upsertCves(cveDataList)
                    totalProcessed += cveDataList.size
                }

                startIndex += resultsPerPage

                logger.info("Processed $startIndex of ${response.totalResults} CVEs (batch of ${response.vulnerabilities.size})")

                // Rate limit: 6 seconds between requests
                // This is safe for both free tier (5 req/30s) and paid tier (50 req/30s)
                if (startIndex < response.totalResults) {
                    delay(6000)
                }

                // Stop if we've fetched all results
                if (startIndex >= response.totalResults) {
                    break
                }

            } catch (e: Exception) {
                logger.error("Error syncing CVEs at index $startIndex", e)
                throw e
            }

        } while (true)

        return totalProcessed
    }

    suspend fun syncSingleCve(cveId: String): NvdCveData? {
        logger.info("Syncing single CVE: $cveId")

        val cveItem = nvdClient.getCveByCveId(cveId) ?: run {
            logger.warn("CVE $cveId not found in NVD")
            return null
        }

        val cveData = nvdClient.mapToNvdCveData(cveItem)
        repository.upsertCve(cveData)

        logger.info("Successfully synced CVE: $cveId")
        return cveData
    }
}

