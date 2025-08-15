package com.auth.service;

import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

public class RedisOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private static final String AUTHORIZATION_PREFIX = "auth-server:oauth2:authorization:";
    private static final String STATE_PREFIX = "auth-server:oauth2:state:";
    private static final String ACCESS_TOKEN_PREFIX = "auth-server:oauth2:access_token:";
    private static final String REFRESH_TOKEN_PREFIX = "auth-server:oauth2:refresh_token:";
    private static final String AUTHORIZATION_CODE_PREFIX = "auth-server:oauth2:auth_code:";

    private RedisTemplate<String, Object> redisTemplate;
    private JpaOAuth2AuthorizationService jpaOAuth2AuthorizationService;

    // Constructor to inject dependencies
    public RedisOAuth2AuthorizationService(RedisTemplate<String, Object> redisTemplate, 
                                          JpaOAuth2AuthorizationService jpaOAuth2AuthorizationService) {
        this.redisTemplate = redisTemplate;
        this.jpaOAuth2AuthorizationService = jpaOAuth2AuthorizationService;
    }

    @Override
    public void save(OAuth2Authorization authorization) {
        // Save to both Redis (for performance) and database (for persistence)
        jpaOAuth2AuthorizationService.save(authorization);
        
        String key = AUTHORIZATION_PREFIX + authorization.getId();
        
        // Cache in Redis with appropriate TTL
        Duration ttl = Duration.ofHours(2); // Default 2 hours
        if (authorization.getRefreshToken() != null) {
            ttl = Duration.ofDays(7); // Refresh tokens last longer
        }
        
        redisTemplate.opsForValue().set(key, authorization, ttl.toSeconds(), TimeUnit.SECONDS);
        
        // Also cache by token values for quick lookup
        if (authorization.getAccessToken() != null) {
            String accessTokenKey = ACCESS_TOKEN_PREFIX + authorization.getAccessToken().getToken().getTokenValue();
            redisTemplate.opsForValue().set(accessTokenKey, authorization.getId(), ttl.toSeconds(), TimeUnit.SECONDS);
        }
        
        if (authorization.getRefreshToken() != null) {
            String refreshTokenKey = REFRESH_TOKEN_PREFIX + authorization.getRefreshToken().getToken().getTokenValue();
            redisTemplate.opsForValue().set(refreshTokenKey, authorization.getId(), Duration.ofDays(7).toSeconds(), TimeUnit.SECONDS);
        }
        
        if (authorization.getToken(OAuth2ParameterNames.CODE) != null) {
            String codeKey = AUTHORIZATION_CODE_PREFIX + authorization.getToken(OAuth2ParameterNames.CODE).getToken().getTokenValue();
            redisTemplate.opsForValue().set(codeKey, authorization.getId(), Duration.ofMinutes(10).toSeconds(), TimeUnit.SECONDS);
        }
    }

    @Override
    @Cacheable(value = "oauth2_authorizations", key = "'id:' + #id")
    public OAuth2Authorization findById(String id) {
        // Try Redis first
        String key = AUTHORIZATION_PREFIX + id;
        OAuth2Authorization authorization = (OAuth2Authorization) redisTemplate.opsForValue().get(key);
        
        if (authorization != null) {
            return authorization;
        }
        
        // Fallback to database
        authorization = jpaOAuth2AuthorizationService.findById(id);
        if (authorization != null) {
            // Cache it in Redis for next time
            redisTemplate.opsForValue().set(key, authorization, Duration.ofHours(2).toSeconds(), TimeUnit.SECONDS);
        }
        
        return authorization;
    }

    @Override
    @Cacheable(value = "oauth2_authorizations", key = "'token:' + #tokenValue + ':' + #tokenType?.value")
    public OAuth2Authorization findByToken(String tokenValue, OAuth2TokenType tokenType) {
        String authorizationId = null;
        
        // Check Redis cache based on token type
        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            authorizationId = (String) redisTemplate.opsForValue().get(ACCESS_TOKEN_PREFIX + tokenValue);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            authorizationId = (String) redisTemplate.opsForValue().get(REFRESH_TOKEN_PREFIX + tokenValue);
        } else if (tokenType != null && "code".equals(tokenType.getValue())) {
            authorizationId = (String) redisTemplate.opsForValue().get(AUTHORIZATION_CODE_PREFIX + tokenValue);
        }
        
        if (authorizationId != null) {
            return findById(authorizationId);
        }
        
        // Fallback to database
        OAuth2Authorization authorization = jpaOAuth2AuthorizationService.findByToken(tokenValue, tokenType);
        if (authorization != null) {
            // Cache the authorization
            save(authorization);
        }
        
        return authorization;
    }

    @Override
    @CacheEvict(value = "oauth2_authorizations", key = "'id:' + #authorization.id")
    public void remove(OAuth2Authorization authorization) {
        // Remove from database
        jpaOAuth2AuthorizationService.remove(authorization);
        
        // Remove from Redis
        String key = AUTHORIZATION_PREFIX + authorization.getId();
        redisTemplate.delete(key);
        
        // Remove token mappings
        if (authorization.getAccessToken() != null) {
            redisTemplate.delete(ACCESS_TOKEN_PREFIX + authorization.getAccessToken().getToken().getTokenValue());
        }
        if (authorization.getRefreshToken() != null) {
            redisTemplate.delete(REFRESH_TOKEN_PREFIX + authorization.getRefreshToken().getToken().getTokenValue());
        }
        if (authorization.getToken(OAuth2ParameterNames.CODE) != null) {
            redisTemplate.delete(AUTHORIZATION_CODE_PREFIX + authorization.getToken(OAuth2ParameterNames.CODE).getToken().getTokenValue());
        }
    }

    // Additional performance methods
    public void evictTokenCache(String tokenValue, OAuth2TokenType tokenType) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            redisTemplate.delete(ACCESS_TOKEN_PREFIX + tokenValue);
        } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            redisTemplate.delete(REFRESH_TOKEN_PREFIX + tokenValue);
        }
    }

    public long getCachedAuthorizationsCount() {
        return redisTemplate.keys(AUTHORIZATION_PREFIX + "*").size();
    }
}