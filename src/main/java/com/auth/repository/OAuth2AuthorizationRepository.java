package com.auth.repository;

import com.auth.entity.OAuth2AuthorizationEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2AuthorizationEntity, String> {

    Optional<OAuth2AuthorizationEntity> findByState(String state);
    
    Optional<OAuth2AuthorizationEntity> findByAuthorizationCodeValue(String authorizationCode);
    
    Optional<OAuth2AuthorizationEntity> findByAccessTokenValue(String accessToken);
    
    Optional<OAuth2AuthorizationEntity> findByRefreshTokenValue(String refreshToken);
    
    Optional<OAuth2AuthorizationEntity> findByOidcIdTokenValue(String idToken);
    
    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE " +
           "a.state = :token OR a.authorizationCodeValue = :token OR " +
           "a.accessTokenValue = :token OR a.refreshTokenValue = :token OR " +
           "a.oidcIdTokenValue = :token")
    Optional<OAuth2AuthorizationEntity> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(@Param("token") String token);
    
    List<OAuth2AuthorizationEntity> findByPrincipalName(String principalName);
    
    @Query("SELECT a FROM OAuth2AuthorizationEntity a WHERE " +
           "(a.authorizationCodeExpiresAt IS NOT NULL AND a.authorizationCodeExpiresAt < :now) OR " +
           "(a.accessTokenExpiresAt IS NOT NULL AND a.accessTokenExpiresAt < :now) OR " +
           "(a.refreshTokenExpiresAt IS NOT NULL AND a.refreshTokenExpiresAt < :now) OR " +
           "(a.oidcIdTokenExpiresAt IS NOT NULL AND a.oidcIdTokenExpiresAt < :now)")
    List<OAuth2AuthorizationEntity> findExpiredTokens(@Param("now") Instant now);
    
    void deleteByAuthorizationCodeExpiresAtBefore(Instant expiredBefore);
    
    void deleteByAccessTokenExpiresAtBefore(Instant expiredBefore);
    
    void deleteByRefreshTokenExpiresAtBefore(Instant expiredBefore);
}