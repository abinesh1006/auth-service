package com.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.ArrayList;

@Component
@ConfigurationProperties(prefix = "oauth2")
public class OAuth2ClientsProperties {

    private List<ClientConfig> clients = new ArrayList<>();

    public List<ClientConfig> getClients() {
        return clients;
    }

    public void setClients(List<ClientConfig> clients) {
        this.clients = clients;
    }

    public static class ClientConfig {
        private String clientId;
        private String clientSecret;
        private String clientName;
        private List<String> redirectUris = new ArrayList<>();
        private List<String> postLogoutRedirectUris = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();
        private List<String> grantTypes = new ArrayList<>();
        private List<String> authMethods = new ArrayList<>();
        private boolean requireConsent = false;

        // Getters and setters
        public String getClientId() {
            return clientId;
        }

        public void setClientId(String clientId) {
            this.clientId = clientId;
        }

        public String getClientSecret() {
            return clientSecret;
        }

        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }

        public String getClientName() {
            return clientName;
        }

        public void setClientName(String clientName) {
            this.clientName = clientName;
        }

        public List<String> getRedirectUris() {
            return redirectUris;
        }

        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }

        // Helper method to set redirect URIs from comma-separated string
        public void setRedirectUris(String redirectUris) {
            if (redirectUris != null && !redirectUris.trim().isEmpty()) {
                this.redirectUris = List.of(redirectUris.split(","));
            }
        }

        public List<String> getPostLogoutRedirectUris() {
            return postLogoutRedirectUris;
        }

        public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) {
            this.postLogoutRedirectUris = postLogoutRedirectUris;
        }

        // Helper method to set post-logout redirect URIs from comma-separated string
        public void setPostLogoutRedirectUris(String postLogoutRedirectUris) {
            if (postLogoutRedirectUris != null && !postLogoutRedirectUris.trim().isEmpty()) {
                this.postLogoutRedirectUris = List.of(postLogoutRedirectUris.split(","));
            }
        }

        public List<String> getScopes() {
            return scopes;
        }

        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }

        // Helper method to set scopes from comma-separated string
        public void setScopes(String scopes) {
            if (scopes != null && !scopes.trim().isEmpty()) {
                this.scopes = List.of(scopes.split(","));
            }
        }

        public List<String> getGrantTypes() {
            return grantTypes;
        }

        public void setGrantTypes(List<String> grantTypes) {
            this.grantTypes = grantTypes;
        }

        // Helper method to set grant types from comma-separated string
        public void setGrantTypes(String grantTypes) {
            if (grantTypes != null && !grantTypes.trim().isEmpty()) {
                this.grantTypes = List.of(grantTypes.split(","));
            }
        }

        public List<String> getAuthMethods() {
            return authMethods;
        }

        public void setAuthMethods(List<String> authMethods) {
            this.authMethods = authMethods;
        }

        // Helper method to set auth methods from comma-separated string
        public void setAuthMethods(String authMethods) {
            if (authMethods != null && !authMethods.trim().isEmpty()) {
                this.authMethods = List.of(authMethods.split(","));
            }
        }

        public boolean isRequireConsent() {
            return requireConsent;
        }

        public void setRequireConsent(boolean requireConsent) {
            this.requireConsent = requireConsent;
        }
    }
}