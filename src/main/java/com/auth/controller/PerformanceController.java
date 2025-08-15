package com.auth.controller;

import com.auth.service.RedisOAuth2AuthorizationService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

@RestController
@RequestMapping("/api/performance")
@Tag(name = "Performance Monitoring", description = "Redis cache performance monitoring and statistics")
public class PerformanceController {

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    @Qualifier("authorizationService")
    private RedisOAuth2AuthorizationService redisAuthorizationService;

    @Operation(
        summary = "Get Redis cache statistics",
        description = "Get detailed statistics about Redis cache usage and performance"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Cache statistics retrieved successfully"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/redis/stats")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getRedisStats() {
        Map<String, Object> stats = new HashMap<>();
        
        // Get Redis connection info
        try {
            // Count cached authorizations
            Set<String> authKeys = redisTemplate.keys("auth-server:oauth2:authorization:*");
            stats.put("cachedAuthorizations", authKeys != null ? authKeys.size() : 0);
            
            // Count cached access tokens
            Set<String> accessTokenKeys = redisTemplate.keys("auth-server:oauth2:access_token:*");
            stats.put("cachedAccessTokens", accessTokenKeys != null ? accessTokenKeys.size() : 0);
            
            // Count cached refresh tokens
            Set<String> refreshTokenKeys = redisTemplate.keys("auth-server:oauth2:refresh_token:*");
            stats.put("cachedRefreshTokens", refreshTokenKeys != null ? refreshTokenKeys.size() : 0);
            
            // Count cached OAuth2 clients
            Set<String> clientKeys = redisTemplate.keys("oauth2_clients::*");
            stats.put("cachedClients", clientKeys != null ? clientKeys.size() : 0);
            
            // Count active sessions
            Set<String> sessionKeys = redisTemplate.keys("auth-service:session:*");
            stats.put("activeSessions", sessionKeys != null ? sessionKeys.size() : 0);
            
            // Redis connection status
            stats.put("redisConnected", true);
            stats.put("status", "Redis cache is operational");
            
        } catch (Exception e) {
            stats.put("redisConnected", false);
            stats.put("status", "Redis cache error: " + e.getMessage());
            stats.put("cachedAuthorizations", 0);
            stats.put("cachedAccessTokens", 0);
            stats.put("cachedRefreshTokens", 0);
            stats.put("cachedClients", 0);
            stats.put("activeSessions", 0);
        }
        
        return ResponseEntity.ok(stats);
    }

    @Operation(
        summary = "Clear Redis cache",
        description = "Clear all Redis cache entries for OAuth2 data (use with caution)"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Cache cleared successfully"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @DeleteMapping("/redis/cache")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, String>> clearRedisCache() {
        Map<String, String> response = new HashMap<>();
        
        try {
            // Clear OAuth2 authorization cache
            Set<String> authKeys = redisTemplate.keys("auth-server:oauth2:*");
            if (authKeys != null && !authKeys.isEmpty()) {
                redisTemplate.delete(authKeys);
            }
            
            // Clear client cache
            Set<String> clientKeys = redisTemplate.keys("oauth2_clients::*");
            if (clientKeys != null && !clientKeys.isEmpty()) {
                redisTemplate.delete(clientKeys);
            }
            
            response.put("status", "success");
            response.put("message", "Redis cache cleared successfully");
            
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Failed to clear cache: " + e.getMessage());
        }
        
        return ResponseEntity.ok(response);
    }

    @Operation(
        summary = "Get system performance metrics",
        description = "Get overall system performance metrics including cache hit rates"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Performance metrics retrieved successfully"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/metrics")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getPerformanceMetrics() {
        Map<String, Object> metrics = new HashMap<>();
        
        // Runtime metrics
        Runtime runtime = Runtime.getRuntime();
        metrics.put("totalMemory", runtime.totalMemory() / (1024 * 1024) + " MB");
        metrics.put("freeMemory", runtime.freeMemory() / (1024 * 1024) + " MB");
        metrics.put("usedMemory", (runtime.totalMemory() - runtime.freeMemory()) / (1024 * 1024) + " MB");
        metrics.put("maxMemory", runtime.maxMemory() / (1024 * 1024) + " MB");
        
        // Cache statistics
        try {
            long cachedAuthorizations = redisAuthorizationService.getCachedAuthorizationsCount();
            metrics.put("cachedAuthorizationsCount", cachedAuthorizations);
            metrics.put("cacheStatus", "Active");
        } catch (Exception e) {
            metrics.put("cachedAuthorizationsCount", 0);
            metrics.put("cacheStatus", "Error: " + e.getMessage());
        }
        
        // Performance recommendations
        if ((runtime.totalMemory() - runtime.freeMemory()) > (runtime.totalMemory() * 0.8)) {
            metrics.put("memoryRecommendation", "Consider increasing JVM heap size or optimizing cache TTL");
        } else {
            metrics.put("memoryRecommendation", "Memory usage is optimal");
        }
        
        return ResponseEntity.ok(metrics);
    }

    @Operation(
        summary = "Test Redis connection",
        description = "Test the connection to Redis and measure response time"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Redis connection test completed"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/redis/test")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> testRedisConnection() {
        Map<String, Object> result = new HashMap<>();
        
        try {
            long startTime = System.currentTimeMillis();
            
            // Test Redis operation
            String testKey = "test-connection-" + System.currentTimeMillis();
            redisTemplate.opsForValue().set(testKey, "test-value", 10, java.util.concurrent.TimeUnit.SECONDS);
            String retrievedValue = (String) redisTemplate.opsForValue().get(testKey);
            redisTemplate.delete(testKey);
            
            long responseTime = System.currentTimeMillis() - startTime;
            
            result.put("status", "success");
            result.put("connected", true);
            result.put("responseTimeMs", responseTime);
            result.put("testPassed", "test-value".equals(retrievedValue));
            result.put("message", "Redis connection is healthy");
            
        } catch (Exception e) {
            result.put("status", "error");
            result.put("connected", false);
            result.put("responseTimeMs", -1);
            result.put("testPassed", false);
            result.put("message", "Redis connection failed: " + e.getMessage());
        }
        
        return ResponseEntity.ok(result);
    }
}