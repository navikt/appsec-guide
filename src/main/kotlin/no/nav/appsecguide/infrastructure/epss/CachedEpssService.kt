package no.nav.appsecguide.infrastructure.epss

import no.nav.appsecguide.infrastructure.cache.Cache
import org.slf4j.LoggerFactory
import java.security.MessageDigest

class CachedEpssService(
    private val epssClient: EpssClient,
    private val cache: Cache<String, Map<String, EpssScore>>
) : EpssService {
    private val logger = LoggerFactory.getLogger(CachedEpssService::class.java)

    companion object {
        // https://api.first.org/epss/
        private const val MAX_PARAMETER_LENGTH = 2000
        // https://github.com/CVEProject/cve-schema/blob/main/schema/CVE_Record_Format.json
        private val CVE_PATTERN = Regex("^CVE-[0-9]{4}-[0-9]{4,19}$")
    }

    override suspend fun getEpssScores(cveIds: List<String>): Map<String, EpssScore> {
        if (cveIds.isEmpty()) {
            return emptyMap()
        }

        val validCveIds = cveIds.filter { it.matches(CVE_PATTERN) }
        val invalidCveIds = cveIds.filterNot { it.matches(CVE_PATTERN) }

        if (invalidCveIds.isNotEmpty()) {
            logger.warn("Filtered out ${invalidCveIds.size} invalid CVE ID(s): ${invalidCveIds.take(5).joinToString(", ")}${if (invalidCveIds.size > 5) "..." else ""}")
        }

        if (validCveIds.isEmpty()) {
            logger.debug("No valid CVE IDs to fetch EPSS scores for")
            return emptyMap()
        }

        val cacheKey = generateCacheKey(validCveIds)

        cache.get(cacheKey)?.let { cachedScores ->
            logger.info("Cache hit for EPSS scores (${validCveIds.size} CVEs)")
            return cachedScores
        }

        logger.debug("Cache miss for EPSS scores, fetching from API for ${validCveIds.size} CVEs")

        return try {
            val batches = createBatches(validCveIds)
            logger.debug("Split ${validCveIds.size} CVEs into ${batches.size} batch(es) to respect 2000 character limit")

            val allScores = batches.flatMap { batch ->
                val response = epssClient.getEpssScores(batch)
                response.data
            }.associateBy { it.cve }

            cache.put(cacheKey, allScores)
            allScores
        } catch (e: EpssRateLimitException) {
            logger.error("Rate limit exceeded for EPSS API. Returning empty scores.")
            emptyMap()
        } catch (e: EpssApiException) {
            logger.error("EPSS API error: ${e.message}. Returning empty scores.")
            emptyMap()
        } catch (e: Exception) {
            logger.error("Unexpected error fetching EPSS scores: ${e.message}", e)
            emptyMap()
        }
    }

    private fun createBatches(cveIds: List<String>): List<List<String>> {
        val batches = mutableListOf<List<String>>()
        val currentBatch = mutableListOf<String>()
        var currentLength = 0

        for (cveId in cveIds) {
            val lengthWithComma = if (currentBatch.isEmpty()) cveId.length else cveId.length + 1

            if (currentLength + lengthWithComma > MAX_PARAMETER_LENGTH && currentBatch.isNotEmpty()) {
                batches.add(currentBatch.toList())
                currentBatch.clear()
                currentLength = 0
            }

            currentBatch.add(cveId)
            currentLength += lengthWithComma
        }

        if (currentBatch.isNotEmpty()) {
            batches.add(currentBatch.toList())
        }

        return batches
    }

    private fun generateCacheKey(cveIds: List<String>): String {
        val sortedCves = cveIds.sorted().joinToString(",")
        val hash = MessageDigest.getInstance("SHA-256")
            .digest(sortedCves.toByteArray())
            .fold("") { str, byte -> str + "%02x".format(byte) }
        return "epss-$hash"
    }
}

