package com.auth.service;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.CachePut;

import com.auth.config.TokenProperties;
import com.auth.entity.OAuth2RegisteredClient;
import com.auth.repository.OAuth2RegisteredClientRepository;

@Service
public class DatabaseRegisteredClientRepository implements RegisteredClientRepository {

    @Autowired
    private OAuth2RegisteredClientRepository clientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private TokenProperties tokenProperties;

    @Override
    @CachePut(value = "oauth2_clients", key = "#registeredClient.clientId")
    public void save(RegisteredClient registeredClient) {
        OAuth2RegisteredClient entity = toEntity(registeredClient);
        clientRepository.save(entity);
    }

    @Override
    @Cacheable(value = "oauth2_clients", key = "'id:' + #id")
    public RegisteredClient findById(String id) {
        return clientRepository.findById(id)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    @Cacheable(value = "oauth2_clients", key = "#clientId")
    public RegisteredClient findByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Cacheable(value = "oauth2_clients", key = "'all_clients'")
    public List<OAuth2RegisteredClient> findAllClients() {
        return clientRepository.findAllEnabledClients();
    }

    @CachePut(value = "oauth2_clients", key = "#client.clientId")
    public OAuth2RegisteredClient saveClient(OAuth2RegisteredClient client) {
        // Encrypt password before saving
        if (client.getClientSecret() != null && !client.getClientSecret().startsWith("{bcrypt}")) {
            client.setClientSecret(passwordEncoder.encode(client.getClientSecret()));
        }
        return clientRepository.save(client);
    }

    @CacheEvict(value = "oauth2_clients", key = "#clientId")
    public void deleteClient(String clientId) {
        clientRepository.findByClientId(clientId)
                .ifPresent(client -> {
                    clientRepository.delete(client);
                    // Also evict the 'all_clients' cache
                    evictAllClientsCache();
                });
    }

    @CacheEvict(value = "oauth2_clients", key = "'all_clients'")
    public void evictAllClientsCache() {
        // This method just evicts the cache
    }

    public boolean existsByClientId(String clientId) {
        return clientRepository.existsByClientId(clientId);
    }

    private RegisteredClient toRegisteredClient(OAuth2RegisteredClient entity) {
        RegisteredClient.Builder builder = RegisteredClient.withId(entity.getId())
                .clientId(entity.getClientId())
                .clientSecret(entity.getClientSecret())
                .clientName(entity.getClientName());

        // Set issued at time
        if (entity.getClientIdIssuedAt() != null) {
            builder.clientIdIssuedAt(entity.getClientIdIssuedAt());
        }

        // Set secret expires at
        if (entity.getClientSecretExpiresAt() != null) {
            builder.clientSecretExpiresAt(entity.getClientSecretExpiresAt());
        }

        // Add authentication methods
        entity.getClientAuthenticationMethods().forEach(method -> {
            switch (method.toLowerCase()) {
                case "client_secret_post":
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
                    break;
                case "client_secret_basic":
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
                    break;
                case "client_secret_jwt":
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_JWT);
                    break;
                case "private_key_jwt":
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
                    break;
                case "none":
                    builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
                    break;
            }
        });

        // Add authorization grant types
        entity.getAuthorizationGrantTypes().forEach(grantType -> {
            switch (grantType.toLowerCase()) {
                case "authorization_code":
                    builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                    break;
                case "refresh_token":
                    builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                    break;
                case "client_credentials":
                    builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    break;
            }
        });

        // Add redirect URIs
        entity.getRedirectUris().forEach(builder::redirectUri);

        // Add post logout redirect URIs  
        entity.getPostLogoutRedirectUris().forEach(builder::postLogoutRedirectUri);

        // Add scopes
        entity.getScopes().forEach(scope -> {
            switch (scope.toLowerCase()) {
                case "openid":
                    builder.scope(OidcScopes.OPENID);
                    break;
                case "profile":
                    builder.scope(OidcScopes.PROFILE);
                    break;
                case "email":
                    builder.scope(OidcScopes.EMAIL);
                    break;
                case "address":
                    builder.scope(OidcScopes.ADDRESS);
                    break;
                case "phone":
                    builder.scope(OidcScopes.PHONE);
                    break;
                default:
                    builder.scope(scope);
                    break;
            }
        });

        // Configure client settings
        builder.clientSettings(ClientSettings.builder()
                .requireAuthorizationConsent(entity.isRequireAuthorizationConsent())
                .requireProofKey(entity.isRequireProofKey())
                .build());

        // Configure token settings
        builder.tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(tokenProperties.getAccessTokenValidity())
                .refreshTokenTimeToLive(tokenProperties.getRefreshTokenValidity())
                .reuseRefreshTokens(tokenProperties.isReuseRefreshTokens())
                .build());

        return builder.build();
    }

    private OAuth2RegisteredClient toEntity(RegisteredClient registeredClient) {
        OAuth2RegisteredClient entity = new OAuth2RegisteredClient();
        entity.setId(registeredClient.getId());
        entity.setClientId(registeredClient.getClientId());
        entity.setClientSecret(registeredClient.getClientSecret());
        entity.setClientName(registeredClient.getClientName());
        entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
        entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());

        // Convert authentication methods
        registeredClient.getClientAuthenticationMethods().forEach(method -> {
            entity.getClientAuthenticationMethods().add(method.getValue());
        });

        // Convert grant types
        registeredClient.getAuthorizationGrantTypes().forEach(grantType -> {
            entity.getAuthorizationGrantTypes().add(grantType.getValue());
        });

        // Set URIs
        entity.setRedirectUris(registeredClient.getRedirectUris());
        entity.setPostLogoutRedirectUris(registeredClient.getPostLogoutRedirectUris());

        // Convert scopes
        registeredClient.getScopes().forEach(scope -> {
            entity.getScopes().add(scope);
        });

        // Set client settings
        if (registeredClient.getClientSettings() != null) {
            entity.setRequireAuthorizationConsent(
                registeredClient.getClientSettings().isRequireAuthorizationConsent());
            entity.setRequireProofKey(
                registeredClient.getClientSettings().isRequireProofKey());
        }

        return entity;
    }
}