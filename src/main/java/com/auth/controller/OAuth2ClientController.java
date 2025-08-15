package com.auth.controller;

import com.auth.entity.OAuth2RegisteredClient;
import com.auth.service.DatabaseRegisteredClientRepository;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/oauth2/clients")
@Tag(name = "OAuth2 Client Management", description = "Manage OAuth2 registered clients dynamically")
public class OAuth2ClientController {

    @Autowired
    private DatabaseRegisteredClientRepository clientRepository;

    @Operation(
        summary = "Get all OAuth2 clients",
        description = "Retrieve all registered OAuth2 clients from the database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Clients retrieved successfully"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<OAuth2RegisteredClient>> getAllClients() {
        List<OAuth2RegisteredClient> clients = clientRepository.findAllClients();
        return ResponseEntity.ok(clients);
    }

    @Operation(
        summary = "Get OAuth2 client by ID",
        description = "Retrieve a specific OAuth2 client by its client ID"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Client found"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<OAuth2RegisteredClient> getClientByClientId(
            @Parameter(description = "OAuth2 Client ID", required = true)
            @PathVariable String clientId) {
        
        return clientRepository.findAllClients().stream()
                .filter(client -> client.getClientId().equals(clientId))
                .findFirst()
                .map(client -> ResponseEntity.ok(client))
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(
        summary = "Create new OAuth2 client",
        description = "Register a new OAuth2 client in the database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "Client created successfully"),
        @ApiResponse(responseCode = "400", description = "Invalid client data"),
        @ApiResponse(responseCode = "409", description = "Client ID already exists"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createClient(
            @Parameter(description = "OAuth2 client configuration", required = true)
            @RequestBody CreateClientRequest request) {
        
        // Check if client ID already exists
        if (clientRepository.existsByClientId(request.clientId)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Client ID '" + request.clientId + "' already exists");
        }

        // Create new client
        OAuth2RegisteredClient client = new OAuth2RegisteredClient();
        client.setClientId(request.clientId);
        client.setClientSecret(request.clientSecret);
        client.setClientName(request.clientName);
        client.setClientAuthenticationMethods(request.authenticationMethods);
        client.setAuthorizationGrantTypes(request.grantTypes);
        client.setRedirectUris(request.redirectUris);
        client.setPostLogoutRedirectUris(request.postLogoutRedirectUris);
        client.setScopes(request.scopes);
        client.setRequireAuthorizationConsent(request.requireConsent);
        client.setRequireProofKey(request.requirePkce);
        client.setEnabled(true);

        OAuth2RegisteredClient savedClient = clientRepository.saveClient(client);
        return ResponseEntity.status(HttpStatus.CREATED).body(savedClient);
    }

    @Operation(
        summary = "Update OAuth2 client",
        description = "Update an existing OAuth2 client configuration"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Client updated successfully"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "400", description = "Invalid client data"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PutMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> updateClient(
            @Parameter(description = "OAuth2 Client ID", required = true)
            @PathVariable String clientId,
            @Parameter(description = "Updated client configuration", required = true)
            @RequestBody UpdateClientRequest request) {
        
        OAuth2RegisteredClient existingClient = clientRepository.findAllClients().stream()
                .filter(client -> client.getClientId().equals(clientId))
                .findFirst()
                .orElse(null);

        if (existingClient == null) {
            return ResponseEntity.notFound().build();
        }

        // Update client properties
        if (request.clientName != null) {
            existingClient.setClientName(request.clientName);
        }
        if (request.clientSecret != null) {
            existingClient.setClientSecret(request.clientSecret);
        }
        if (request.authenticationMethods != null) {
            existingClient.setClientAuthenticationMethods(request.authenticationMethods);
        }
        if (request.grantTypes != null) {
            existingClient.setAuthorizationGrantTypes(request.grantTypes);
        }
        if (request.redirectUris != null) {
            existingClient.setRedirectUris(request.redirectUris);
        }
        if (request.postLogoutRedirectUris != null) {
            existingClient.setPostLogoutRedirectUris(request.postLogoutRedirectUris);
        }
        if (request.scopes != null) {
            existingClient.setScopes(request.scopes);
        }
        if (request.requireConsent != null) {
            existingClient.setRequireAuthorizationConsent(request.requireConsent);
        }
        if (request.requirePkce != null) {
            existingClient.setRequireProofKey(request.requirePkce);
        }
        if (request.enabled != null) {
            existingClient.setEnabled(request.enabled);
        }

        OAuth2RegisteredClient updatedClient = clientRepository.saveClient(existingClient);
        return ResponseEntity.ok(updatedClient);
    }

    @Operation(
        summary = "Delete OAuth2 client",
        description = "Remove an OAuth2 client from the database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "204", description = "Client deleted successfully"),
        @ApiResponse(responseCode = "404", description = "Client not found"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @DeleteMapping("/{clientId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteClient(
            @Parameter(description = "OAuth2 Client ID", required = true)
            @PathVariable String clientId) {
        
        if (!clientRepository.existsByClientId(clientId)) {
            return ResponseEntity.notFound().build();
        }

        clientRepository.deleteClient(clientId);
        return ResponseEntity.noContent().build();
    }

    // Request DTOs
    @Schema(description = "Request object for creating a new OAuth2 client")
    public static class CreateClientRequest {
        @Schema(description = "Unique client identifier", example = "my-app-client")
        public String clientId;
        
        @Schema(description = "Client secret", example = "my-secure-secret")
        public String clientSecret;
        
        @Schema(description = "Human-readable client name", example = "My Application")
        public String clientName;
        
        @Schema(description = "Client authentication methods", example = "[\"client_secret_post\", \"client_secret_basic\"]")
        public Set<String> authenticationMethods;
        
        @Schema(description = "Authorization grant types", example = "[\"authorization_code\", \"refresh_token\"]")
        public Set<String> grantTypes;
        
        @Schema(description = "Redirect URIs", example = "[\"http://localhost:3000/callback\"]")
        public Set<String> redirectUris;
        
        @Schema(description = "Post logout redirect URIs", example = "[\"http://localhost:3000/logout\"]")
        public Set<String> postLogoutRedirectUris;
        
        @Schema(description = "OAuth2 scopes", example = "[\"openid\", \"profile\", \"read\"]")
        public Set<String> scopes;
        
        @Schema(description = "Require authorization consent", example = "false")
        public boolean requireConsent = false;
        
        @Schema(description = "Require PKCE", example = "true")
        public boolean requirePkce = false;
    }

    @Schema(description = "Request object for updating an OAuth2 client")
    public static class UpdateClientRequest {
        @Schema(description = "Human-readable client name", example = "My Updated Application")
        public String clientName;
        
        @Schema(description = "Client secret", example = "new-secure-secret")
        public String clientSecret;
        
        @Schema(description = "Client authentication methods", example = "[\"client_secret_post\"]")
        public Set<String> authenticationMethods;
        
        @Schema(description = "Authorization grant types", example = "[\"authorization_code\", \"refresh_token\", \"client_credentials\"]")
        public Set<String> grantTypes;
        
        @Schema(description = "Redirect URIs", example = "[\"http://localhost:3000/callback\", \"http://localhost:3000/auth\"]")
        public Set<String> redirectUris;
        
        @Schema(description = "Post logout redirect URIs", example = "[\"http://localhost:3000/logout\"]")
        public Set<String> postLogoutRedirectUris;
        
        @Schema(description = "OAuth2 scopes", example = "[\"openid\", \"profile\", \"read\", \"write\"]")
        public Set<String> scopes;
        
        @Schema(description = "Require authorization consent", example = "true")
        public Boolean requireConsent;
        
        @Schema(description = "Require PKCE", example = "false")
        public Boolean requirePkce;
        
        @Schema(description = "Client enabled status", example = "true")
        public Boolean enabled;
    }
}