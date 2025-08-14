package com.auth.service;

import com.auth.repository.OAuth2AuthorizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@Transactional
public class LogoutService {

    @Autowired
    private OAuth2AuthorizationRepository authorizationRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    /**
     * Complete logout that revokes all OAuth2 tokens for the user
     */
    public void performCompleteLogout(Authentication authentication) {
        if (authentication != null && authentication.getName() != null) {
            String principalName = authentication.getName();
            
            // Find and remove all OAuth2 authorizations for this user
            var authorizations = authorizationRepository.findByPrincipalName(principalName);
            
            for (var authEntity : authorizations) {
                // Remove from the authorization service (this handles the in-memory cache)
                var oauth2Auth = authorizationService.findById(authEntity.getId());
                if (oauth2Auth != null) {
                    authorizationService.remove(oauth2Auth);
                }
            }
            
            // Also clean up expired tokens while we're at it
            cleanupExpiredTokens();
        }
    }

    /**
     * Cleanup expired tokens from the database
     */
    public void cleanupExpiredTokens() {
        Instant now = Instant.now();
        var expiredTokens = authorizationRepository.findExpiredTokens(now);
        
        for (var expiredToken : expiredTokens) {
            authorizationRepository.delete(expiredToken);
        }
    }

    /**
     * Revoke specific OAuth2 authorization by token
     */
    public boolean revokeToken(String token) {
        try {
            var oauth2Auth = authorizationService.findByToken(token, null);
            if (oauth2Auth != null) {
                authorizationService.remove(oauth2Auth);
                return true;
            }
            return false;
        } catch (Exception e) {
            return false;
        }
    }
}