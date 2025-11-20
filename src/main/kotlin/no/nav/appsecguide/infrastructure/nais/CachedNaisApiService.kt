package no.nav.appsecguide.infrastructure.nais

import no.nav.appsecguide.infrastructure.cache.ValkeyCache
import org.slf4j.LoggerFactory
import java.security.MessageDigest

class CachedNaisApiService(
    private val delegate: NaisApiClient,
    private val teamIngressCache: ValkeyCache<String, TeamIngressTypesResponse>,
    private val userAppsCache: ValkeyCache<String, ApplicationsForUserResponse>
) : NaisApiService {
    private val logger = LoggerFactory.getLogger(CachedNaisApiService::class.java)

    override suspend fun getTeamIngressTypes(teamSlug: String): TeamIngressTypesResponse {
        val cacheKey = generateCacheKey("team:$teamSlug")

        teamIngressCache.get(cacheKey)?.let { cachedResponse ->
            return cachedResponse
        }

        val response = delegate.getTeamIngressTypes(teamSlug)

        if (response.errors != null && response.errors.isNotEmpty()) {
            logger.warn("Not caching error response for team: $teamSlug")
        } else {
            teamIngressCache.put(cacheKey, response)
        }

        return response
    }

    override suspend fun getApplicationsForUser(email: String): ApplicationsForUserResponse {
        val cacheKey = generateCacheKey("user:$email")

        userAppsCache.get(cacheKey)?.let { cachedResponse ->
            return cachedResponse
        }

        val response = delegate.getApplicationsForUser(email)

        if (response.errors != null && response.errors.isNotEmpty()) {
            logger.warn("Not caching error response for user: $email")
        } else {
            userAppsCache.put(cacheKey, response)
        }

        return response
    }

    private fun generateCacheKey(prefix: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hashBytes = digest.digest(prefix.toByteArray())
        return hashBytes.joinToString("") { "%02x".format(it) }.take(16)
    }
}

