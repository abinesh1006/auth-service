package com.auth.controller;

import com.auth.service.LogoutService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/token")
@Tag(name = "Token Management", description = "JWT token validation, information, and management endpoints")
public class TokenController {

    @Autowired
    private LogoutService logoutService;

    @Operation(
        summary = "Get JWT token information",
        description = "Retrieve detailed information about the current JWT token including claims, expiration, and active token count from database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token information retrieved successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "subject": "user123",
                          "issuer": "http://localhost:8080",
                          "audience": ["auth-client"],
                          "issuedAt": "2025-08-14T10:00:00Z",
                          "expiresAt": "2025-08-14T11:00:00Z",
                          "scopes": ["openid", "profile", "read"],
                          "activeTokenCount": 3,
                          "claims": {
                            "sub": "user123",
                            "aud": ["auth-client"],
                            "scope": "openid profile read"
                          }
                        }"""))),
        @ApiResponse(responseCode = "400", description = "Invalid token", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = "{\"error\": \"Invalid token\"}"))),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getTokenInfo(
        @Parameter(description = "Authenticated user with JWT token", hidden = true)
        Authentication authentication) {
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
            
            // Add database-related information
            String username = jwt.getSubject();
            int activeTokenCount = logoutService.getActiveTokenCount(username);
            tokenInfo.put("activeTokenCount", activeTokenCount);
            
            return ResponseEntity.ok(tokenInfo);
        }
        
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
    }

    @Operation(
        summary = "Validate JWT token",
        description = "Validate if the current JWT token is valid and return user information with active token count"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token validation result", 
                    content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(name = "Valid Token", value = """
                            {
                              "valid": true,
                              "username": "user123",
                              "authorities": ["ROLE_USER"],
                              "activeTokens": 3
                            }"""),
                        @ExampleObject(name = "Invalid Token", value = """
                            {
                              "valid": false,
                              "error": "Token is not valid or expired"
                            }""")
                    })),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validateToken(
        @Parameter(description = "Authenticated user information", hidden = true)
        Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.isAuthenticated()) {
            response.put("valid", true);
            response.put("username", authentication.getName());
            response.put("authorities", authentication.getAuthorities());
            
            // Add database token information
            int activeTokens = logoutService.getActiveTokenCount(authentication.getName());
            response.put("activeTokens", activeTokens);
        } else {
            response.put("valid", false);
            response.put("error", "Token is not valid or expired");
        }
        
        return ResponseEntity.ok(response);
    }

    @Operation(
        summary = "Revoke specific token",
        description = "Revoke a specific OAuth2 token from the database by token value"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token revocation result", 
                    content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(name = "Success", value = """
                            {
                              "success": true,
                              "message": "Token successfully revoked from database"
                            }"""),
                        @ExampleObject(name = "Not Found", value = """
                            {
                              "success": false,
                              "message": "Token not found or already revoked"
                            }""")
                    })),
        @ApiResponse(responseCode = "401", description = "Unauthorized",
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": false,
                          "message": "Unauthorized"
                        }""")))
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/revoke")
    public ResponseEntity<Map<String, Object>> revokeToken(
        @Parameter(description = "JWT token to revoke", required = true, 
                  example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIn0...")
        @RequestParam String token, 
        @Parameter(description = "Authenticated user information", hidden = true)
        Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.isAuthenticated()) {
            boolean revoked = logoutService.revokeToken(token);
            
            if (revoked) {
                response.put("success", true);
                response.put("message", "Token successfully revoked from database");
            } else {
                response.put("success", false);
                response.put("message", "Token not found or already revoked");
            }
        } else {
            response.put("success", false);
            response.put("message", "Unauthorized");
        }
        
        return ResponseEntity.ok(response);
    }

    @Operation(
        summary = "Get active token count",
        description = "Get the number of active OAuth2 tokens for the current user from database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Active token count retrieved successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "username": "user123",
                          "activeTokenCount": 3,
                          "success": true
                        }"""))),
        @ApiResponse(responseCode = "401", description = "Unauthorized",
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": false,
                          "message": "Unauthorized"
                        }""")))
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/count")
    public ResponseEntity<Map<String, Object>> getActiveTokenCount(
        @Parameter(description = "Authenticated user information", hidden = true)
        Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            int count = logoutService.getActiveTokenCount(username);
            
            response.put("username", username);
            response.put("activeTokenCount", count);
            response.put("success", true);
        } else {
            response.put("success", false);
            response.put("message", "Unauthorized");
        }
        
        return ResponseEntity.ok(response);
    }

    @Operation(
        summary = "Revoke all user tokens",
        description = "Revoke all OAuth2 tokens for the current user (complete database logout)"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "All tokens revoked successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": true,
                          "message": "All tokens revoked from database",
                          "revokedTokenCount": 3,
                          "username": "user123"
                        }"""))),
        @ApiResponse(responseCode = "401", description = "Unauthorized",
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": false,
                          "message": "Unauthorized"
                        }""")))
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/revoke-all")
    public ResponseEntity<Map<String, Object>> revokeAllTokens(
        @Parameter(description = "Authenticated user information", hidden = true)
        Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.isAuthenticated()) {
            String username = authentication.getName();
            
            // Get count before revocation
            int initialCount = logoutService.getActiveTokenCount(username);
            
            // Perform complete logout
            logoutService.performCompleteLogout(authentication);
            
            response.put("success", true);
            response.put("message", "All tokens revoked from database");
            response.put("revokedTokenCount", initialCount);
            response.put("username", username);
        } else {
            response.put("success", false);
            response.put("message", "Unauthorized");
        }
        
        return ResponseEntity.ok(response);
    }

    @Operation(
        summary = "Revoke user tokens (Admin)",
        description = "Admin endpoint to revoke all tokens for a specific user"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Admin token revocation result", 
                    content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(name = "Success", value = """
                            {
                              "success": true,
                              "message": "All tokens revoked for user: targetUser",
                              "revokedTokenCount": 2,
                              "targetUser": "targetUser",
                              "adminUser": "admin123"
                            }"""),
                        @ExampleObject(name = "Failed", value = """
                            {
                              "success": false,
                              "message": "Failed to revoke tokens for user: targetUser"
                            }""")
                    })),
        @ApiResponse(responseCode = "403", description = "Insufficient privileges",
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": false,
                          "message": "Admin privileges required"
                        }""")))
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/admin/revoke-user-tokens")
    public ResponseEntity<Map<String, Object>> revokeUserTokens(
        @Parameter(description = "Username of the user whose tokens should be revoked", 
                  required = true, example = "user123")
        @RequestParam String username, 
        @Parameter(description = "Admin user information", hidden = true)
        Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))) {
            
            int initialCount = logoutService.getActiveTokenCount(username);
            boolean success = logoutService.revokeAllUserTokens(username);
            
            if (success) {
                response.put("success", true);
                response.put("message", "All tokens revoked for user: " + username);
                response.put("revokedTokenCount", initialCount);
                response.put("targetUser", username);
                response.put("adminUser", authentication.getName());
            } else {
                response.put("success", false);
                response.put("message", "Failed to revoke tokens for user: " + username);
            }
        } else {
            response.put("success", false);
            response.put("message", "Admin privileges required");
        }
        
        return ResponseEntity.ok(response);
    }

    @Operation(
        summary = "Cleanup expired tokens (Admin)",
        description = "Admin endpoint to cleanup expired tokens from the database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Expired tokens cleanup completed", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": true,
                          "message": "Expired tokens cleanup completed",
                          "cleanedTokenCount": 15,
                          "adminUser": "admin123"
                        }"""))),
        @ApiResponse(responseCode = "403", description = "Insufficient privileges",
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "success": false,
                          "message": "Admin privileges required"
                        }""")))
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/admin/cleanup-expired")
    public ResponseEntity<Map<String, Object>> cleanupExpiredTokens(
        @Parameter(description = "Admin user information", hidden = true)
        Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("ROLE_ADMIN"))) {
            
            int cleanedCount = logoutService.cleanupExpiredTokens();
            
            response.put("success", true);
            response.put("message", "Expired tokens cleanup completed");
            response.put("cleanedTokenCount", cleanedCount);
            response.put("adminUser", authentication.getName());
        } else {
            response.put("success", false);
            response.put("message", "Admin privileges required");
        }
        
        return ResponseEntity.ok(response);
    }
}