package com.auth.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/token")
public class TokenController {

    /**
     * Endpoint to validate and get information about the current JWT token
     */
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getTokenInfo(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Jwt jwt = jwtAuth.getToken();
            
            Map<String, Object> tokenInfo = new HashMap<>();
            tokenInfo.put("subject", jwt.getSubject());
            tokenInfo.put("issuer", jwt.getIssuer());
            tokenInfo.put("audience", jwt.getAudience());
            tokenInfo.put("issuedAt", jwt.getIssuedAt());
            tokenInfo.put("expiresAt", jwt.getExpiresAt());
            tokenInfo.put("scopes", jwt.getClaimAsStringList("scope"));
            tokenInfo.put("claims", jwt.getClaims());
            
            return ResponseEntity.ok(tokenInfo);
        }
        
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
    }

    /**
     * Endpoint to validate if a JWT token is valid
     */
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.isAuthenticated()) {
            response.put("valid", true);
            response.put("username", authentication.getName());
            response.put("authorities", authentication.getAuthorities());
        } else {
            response.put("valid", false);
            response.put("message", "Token is invalid or expired");
        }
        
        return ResponseEntity.ok(response);
    }
}