package com.auth.service;

import com.auth.repository.OAuth2AuthorizationRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Instant;

@Service
@Transactional
public class LogoutService {

    private static final Logger logger = LoggerFactory.getLogger(LogoutService.class);

    @Autowired
    private OAuth2AuthorizationRepository authorizationRepository;

    @Autowired
    private OAuth2AuthorizationService authorizationService;

    /**
     * Complete logout that revokes all OAuth2 tokens for the user
     * and logs the activity to the database
     */
    public void performCompleteLogout(Authentication authentication) {
        if (authentication != null && authentication.getName() != null) {
            String principalName = authentication.getName();
            logger.info("Performing complete logout for user: {}", principalName);
            
            try {
                // Find and remove all OAuth2 authorizations for this user
                var authorizations = authorizationRepository.findByPrincipalName(principalName);
                int tokenCount = authorizations.size();
                
                logger.info("Found {} OAuth2 authorizations for user: {}", tokenCount, principalName);
                
                for (var authEntity : authorizations) {
                    // Remove from the authorization service (this handles the in-memory cache)
                    var oauth2Auth = authorizationService.findById(authEntity.getId());
                    if (oauth2Auth != null) {
                        authorizationService.remove(oauth2Auth);
                        logger.debug("Removed OAuth2 authorization with ID: {}", authEntity.getId());
                    }
                }
                
                // Also clean up expired tokens while we're at it
                int expiredTokensRemoved = cleanupExpiredTokens();
                
                logger.info("Logout completed for user: {}. Revoked {} active tokens, cleaned up {} expired tokens", 
                           principalName, tokenCount, expiredTokensRemoved);
                
            } catch (Exception e) {
                logger.error("Error during logout for user: {}", principalName, e);
                // Don't throw exception to avoid disrupting the logout process
            }
        }
    }

    /**
     * Cleanup expired tokens from the database
     * Returns the number of tokens removed
     */
    public int cleanupExpiredTokens() {
        try {
            Instant now = Instant.now();
            var expiredTokens = authorizationRepository.findExpiredTokens(now);
            int count = expiredTokens.size();
            
            if (count > 0) {
                logger.info("Cleaning up {} expired tokens", count);
                for (var expiredToken : expiredTokens) {
                    authorizationRepository.delete(expiredToken);
                }
                logger.info("Successfully cleaned up {} expired tokens", count);
            }
            
            return count;
        } catch (Exception e) {
            logger.error("Error during expired token cleanup", e);
            return 0;
        }
    }

    /**
     * Revoke specific OAuth2 authorization by token
     */
    public boolean revokeToken(String token) {
        try {
            logger.info("Attempting to revoke token");
            var oauth2Auth = authorizationService.findByToken(token, null);
            if (oauth2Auth != null) {
                String principalName = oauth2Auth.getPrincipalName();
                authorizationService.remove(oauth2Auth);
                logger.info("Successfully revoked token for user: {}", principalName);
                return true;
            } else {
                logger.warn("Token not found for revocation");
                return false;
            }
        } catch (Exception e) {
            logger.error("Error during token revocation", e);
            return false;
        }
    }

    /**
     * Get active token count for a user
     */
    public int getActiveTokenCount(String principalName) {
        try {
            var authorizations = authorizationRepository.findByPrincipalName(principalName);
            int count = authorizations.size();
            logger.debug("User {} has {} active tokens", principalName, count);
            return count;
        } catch (Exception e) {
            logger.error("Error getting active token count for user: {}", principalName, e);
            return 0;
        }
    }

    /**
     * Revoke all tokens for a specific user (admin function)
     */
    @Transactional
    public boolean revokeAllUserTokens(String principalName) {
        try {
            logger.info("Admin action: Revoking all tokens for user: {}", principalName);
            var authorizations = authorizationRepository.findByPrincipalName(principalName);
            int count = 0;
            
            for (var authEntity : authorizations) {
                var oauth2Auth = authorizationService.findById(authEntity.getId());
                if (oauth2Auth != null) {
                    authorizationService.remove(oauth2Auth);
                    count++;
                }
            }
            
            logger.info("Successfully revoked {} tokens for user: {}", count, principalName);
            return true;
        } catch (Exception e) {
            logger.error("Error revoking all tokens for user: {}", principalName, e);
            return false;
        }
    }
}