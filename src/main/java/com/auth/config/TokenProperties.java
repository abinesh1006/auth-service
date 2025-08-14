package com.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.time.Duration;

@Component
@ConfigurationProperties(prefix = "oauth2.token")
public class TokenProperties {

    private Duration accessTokenValidity = Duration.ofMinutes(5);
    private Duration refreshTokenValidity = Duration.ofMinutes(60);
    private Duration idTokenValidity = Duration.ofMinutes(5);
    private boolean reuseRefreshTokens = false;

    // Getters and Setters
    public Duration getAccessTokenValidity() {
        return accessTokenValidity;
    }

    public void setAccessTokenValidity(Duration accessTokenValidity) {
        this.accessTokenValidity = accessTokenValidity;
    }

    public Duration getRefreshTokenValidity() {
        return refreshTokenValidity;
    }

    public void setRefreshTokenValidity(Duration refreshTokenValidity) {
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public Duration getIdTokenValidity() {
        return idTokenValidity;
    }

    public void setIdTokenValidity(Duration idTokenValidity) {
        this.idTokenValidity = idTokenValidity;
    }

    public boolean isReuseRefreshTokens() {
        return reuseRefreshTokens;
    }

    public void setReuseRefreshTokens(boolean reuseRefreshTokens) {
        this.reuseRefreshTokens = reuseRefreshTokens;
    }
}