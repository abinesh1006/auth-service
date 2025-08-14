package com.auth.entity;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "oauth2_authorization")
public class OAuth2AuthorizationEntity {
    
    @Id
    private String id;
    
    @Column(name = "registered_client_id")
    private String registeredClientId;
    
    @Column(name = "principal_name")
    private String principalName;
    
    @Column(name = "authorization_grant_type")
    private String authorizationGrantType;
    
    @Lob
    @Column(name = "authorized_scopes")
    private String authorizedScopes;
    
    @Lob
    @Column(name = "attributes")
    private String attributes;
    
    @Lob
    @Column(name = "state")
    private String state;
    
    @Lob
    @Column(name = "authorization_code_value")
    private String authorizationCodeValue;
    
    @Column(name = "authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;
    
    @Column(name = "authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;
    
    @Column(name = "authorization_code_metadata")
    private String authorizationCodeMetadata;
    
    @Lob
    @Column(name = "access_token_value")
    private String accessTokenValue;
    
    @Column(name = "access_token_issued_at")
    private Instant accessTokenIssuedAt;
    
    @Column(name = "access_token_expires_at")
    private Instant accessTokenExpiresAt;
    
    @Lob
    @Column(name = "access_token_metadata")
    private String accessTokenMetadata;
    
    @Column(name = "access_token_type")
    private String accessTokenType;
    
    @Lob
    @Column(name = "access_token_scopes")
    private String accessTokenScopes;
    
    @Lob
    @Column(name = "refresh_token_value")
    private String refreshTokenValue;
    
    @Column(name = "refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;
    
    @Column(name = "refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;
    
    @Lob
    @Column(name = "refresh_token_metadata")
    private String refreshTokenMetadata;
    
    @Lob
    @Column(name = "oidc_id_token_value")
    private String oidcIdTokenValue;
    
    @Column(name = "oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;
    
    @Column(name = "oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;
    
    @Lob
    @Column(name = "oidc_id_token_metadata")
    private String oidcIdTokenMetadata;
    
    @Lob
    @Column(name = "oidc_id_token_claims")
    private String oidcIdTokenClaims;
    
    // Constructors, getters, setters...
    public OAuth2AuthorizationEntity() {}
    
    // Add getters and setters for all fields
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    
    public String getRegisteredClientId() { return registeredClientId; }
    public void setRegisteredClientId(String registeredClientId) { this.registeredClientId = registeredClientId; }
    
    public String getPrincipalName() { return principalName; }
    public void setPrincipalName(String principalName) { this.principalName = principalName; }
    
    public String getAuthorizationGrantType() { return authorizationGrantType; }
    public void setAuthorizationGrantType(String authorizationGrantType) { this.authorizationGrantType = authorizationGrantType; }
    
    public String getAuthorizedScopes() { return authorizedScopes; }
    public void setAuthorizedScopes(String authorizedScopes) { this.authorizedScopes = authorizedScopes; }
    
    public String getAttributes() { return attributes; }
    public void setAttributes(String attributes) { this.attributes = attributes; }
    
    public String getState() { return state; }
    public void setState(String state) { this.state = state; }
    
    public String getAuthorizationCodeValue() { return authorizationCodeValue; }
    public void setAuthorizationCodeValue(String authorizationCodeValue) { this.authorizationCodeValue = authorizationCodeValue; }
    
    public Instant getAuthorizationCodeIssuedAt() { return authorizationCodeIssuedAt; }
    public void setAuthorizationCodeIssuedAt(Instant authorizationCodeIssuedAt) { this.authorizationCodeIssuedAt = authorizationCodeIssuedAt; }
    
    public Instant getAuthorizationCodeExpiresAt() { return authorizationCodeExpiresAt; }
    public void setAuthorizationCodeExpiresAt(Instant authorizationCodeExpiresAt) { this.authorizationCodeExpiresAt = authorizationCodeExpiresAt; }
    
    public String getAuthorizationCodeMetadata() { return authorizationCodeMetadata; }
    public void setAuthorizationCodeMetadata(String authorizationCodeMetadata) { this.authorizationCodeMetadata = authorizationCodeMetadata; }
    
    public String getAccessTokenValue() { return accessTokenValue; }
    public void setAccessTokenValue(String accessTokenValue) { this.accessTokenValue = accessTokenValue; }
    
    public Instant getAccessTokenIssuedAt() { return accessTokenIssuedAt; }
    public void setAccessTokenIssuedAt(Instant accessTokenIssuedAt) { this.accessTokenIssuedAt = accessTokenIssuedAt; }
    
    public Instant getAccessTokenExpiresAt() { return accessTokenExpiresAt; }
    public void setAccessTokenExpiresAt(Instant accessTokenExpiresAt) { this.accessTokenExpiresAt = accessTokenExpiresAt; }
    
    public String getAccessTokenMetadata() { return accessTokenMetadata; }
    public void setAccessTokenMetadata(String accessTokenMetadata) { this.accessTokenMetadata = accessTokenMetadata; }
    
    public String getAccessTokenType() { return accessTokenType; }
    public void setAccessTokenType(String accessTokenType) { this.accessTokenType = accessTokenType; }
    
    public String getAccessTokenScopes() { return accessTokenScopes; }
    public void setAccessTokenScopes(String accessTokenScopes) { this.accessTokenScopes = accessTokenScopes; }
    
    public String getRefreshTokenValue() { return refreshTokenValue; }
    public void setRefreshTokenValue(String refreshTokenValue) { this.refreshTokenValue = refreshTokenValue; }
    
    public Instant getRefreshTokenIssuedAt() { return refreshTokenIssuedAt; }
    public void setRefreshTokenIssuedAt(Instant refreshTokenIssuedAt) { this.refreshTokenIssuedAt = refreshTokenIssuedAt; }
    
    public Instant getRefreshTokenExpiresAt() { return refreshTokenExpiresAt; }
    public void setRefreshTokenExpiresAt(Instant refreshTokenExpiresAt) { this.refreshTokenExpiresAt = refreshTokenExpiresAt; }
    
    public String getRefreshTokenMetadata() { return refreshTokenMetadata; }
    public void setRefreshTokenMetadata(String refreshTokenMetadata) { this.refreshTokenMetadata = refreshTokenMetadata; }
    
    public String getOidcIdTokenValue() { return oidcIdTokenValue; }
    public void setOidcIdTokenValue(String oidcIdTokenValue) { this.oidcIdTokenValue = oidcIdTokenValue; }
    
    public Instant getOidcIdTokenIssuedAt() { return oidcIdTokenIssuedAt; }
    public void setOidcIdTokenIssuedAt(Instant oidcIdTokenIssuedAt) { this.oidcIdTokenIssuedAt = oidcIdTokenIssuedAt; }
    
    public Instant getOidcIdTokenExpiresAt() { return oidcIdTokenExpiresAt; }
    public void setOidcIdTokenExpiresAt(Instant oidcIdTokenExpiresAt) { this.oidcIdTokenExpiresAt = oidcIdTokenExpiresAt; }
    
    public String getOidcIdTokenMetadata() { return oidcIdTokenMetadata; }
    public void setOidcIdTokenMetadata(String oidcIdTokenMetadata) { this.oidcIdTokenMetadata = oidcIdTokenMetadata; }
    
    public String getOidcIdTokenClaims() { return oidcIdTokenClaims; }
    public void setOidcIdTokenClaims(String oidcIdTokenClaims) { this.oidcIdTokenClaims = oidcIdTokenClaims; }
}