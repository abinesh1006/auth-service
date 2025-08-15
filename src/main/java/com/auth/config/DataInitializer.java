package com.auth.config;

import com.auth.service.UserService;
import com.auth.entity.OAuth2RegisteredClient;
import com.auth.service.DatabaseRegisteredClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserService userService;

    @Autowired
    private DatabaseRegisteredClientRepository clientRepository;

    @Override
    public void run(String... args) throws Exception {
        initializeDefaultUsers();
        initializeDefaultClients();
    }

    private void initializeDefaultUsers() {
        // Create a default admin user
        try {
            userService.createUser("admin", "admin@example.com", "admin123");
            System.out.println("Default admin user created: admin / admin123");
        } catch (RuntimeException e) {
            System.out.println("Admin user already exists or failed to create: " + e.getMessage());
        }

        // Create a test user
        try {
            userService.createUser("testuser", "test@example.com", "test123");
            System.out.println("Test user created: testuser / test123");
        } catch (RuntimeException e) {
            System.out.println("Test user already exists or failed to create: " + e.getMessage());
        }
    }

    private void initializeDefaultClients() {
        // Check if clients already exist
        if (clientRepository.findAllClients().isEmpty()) {
            
            // Client 1 - Main Web Application
            OAuth2RegisteredClient webClient = new OAuth2RegisteredClient();
            webClient.setClientId("auth-client");
            webClient.setClientSecret("secret"); // Will be encrypted by the service
            webClient.setClientName("Main Web Application");
            webClient.setClientAuthenticationMethods(Set.of("client_secret_post", "client_secret_basic"));
            webClient.setAuthorizationGrantTypes(Set.of("authorization_code", "refresh_token"));
            webClient.setRedirectUris(Set.of(
                "http://127.0.0.1:8080/login/oauth2/code/auth-client",
                "http://127.0.0.1:8080/authorized",
                "http://localhost:8080/swagger-ui/oauth2-redirect.html",
                "https://oauth.pstmn.io/v1/callback"
            ));
            webClient.setPostLogoutRedirectUris(Set.of("http://127.0.0.1:8080/"));
            webClient.setScopes(Set.of("openid", "profile", "read", "write"));
            webClient.setRequireAuthorizationConsent(false);
            webClient.setRequireProofKey(false);
            
            // Client 2 - Mobile Application
            OAuth2RegisteredClient mobileClient = new OAuth2RegisteredClient();
            mobileClient.setClientId("mobile-app");
            mobileClient.setClientSecret("mobile-secret");
            mobileClient.setClientName("Mobile Application");
            mobileClient.setClientAuthenticationMethods(Set.of("client_secret_post"));
            mobileClient.setAuthorizationGrantTypes(Set.of("authorization_code", "refresh_token"));
            mobileClient.setRedirectUris(Set.of(
                "com.example.mobile://oauth/callback",
                "http://localhost:3000/callback"
            ));
            mobileClient.setPostLogoutRedirectUris(Set.of("com.example.mobile://logout"));
            mobileClient.setScopes(Set.of("openid", "profile", "read"));
            mobileClient.setRequireAuthorizationConsent(true);
            mobileClient.setRequireProofKey(true); // PKCE for mobile
            
            // Client 3 - API Client
            OAuth2RegisteredClient apiClient = new OAuth2RegisteredClient();
            apiClient.setClientId("api-client");
            apiClient.setClientSecret("api-secret");
            apiClient.setClientName("API Client");
            apiClient.setClientAuthenticationMethods(Set.of("client_secret_basic"));
            apiClient.setAuthorizationGrantTypes(Set.of("authorization_code", "refresh_token", "client_credentials"));
            apiClient.setRedirectUris(Set.of("https://api.example.com/oauth/callback"));
            apiClient.setPostLogoutRedirectUris(Set.of("https://api.example.com/logout"));
            apiClient.setScopes(Set.of("read", "write"));
            apiClient.setRequireAuthorizationConsent(false);
            apiClient.setRequireProofKey(false);
            
            // Save all clients
            clientRepository.saveClient(webClient);
            clientRepository.saveClient(mobileClient);
            clientRepository.saveClient(apiClient);
            
            System.out.println("✅ Initialized 3 default OAuth2 clients in database");
            System.out.println("   - auth-client (Web App)");
            System.out.println("   - mobile-app (Mobile App with PKCE)"); 
            System.out.println("   - api-client (API with Client Credentials)");
        } else {
            System.out.println("📋 OAuth2 clients already exist in database: " + 
                clientRepository.findAllClients().size() + " clients found");
        }
    }
}