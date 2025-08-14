package com.auth.entity;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Collections;
import java.util.UUID;

@Entity
@Table(name = "users")
@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
@JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, getterVisibility = JsonAutoDetect.Visibility.NONE, 
                isGetterVisibility = JsonAutoDetect.Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public class User implements UserDetails {

    private static final long serialVersionUID = 1L;

	@Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @JsonProperty("id")
    private UUID id;

    @Column(unique = true, nullable = false)
    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @JsonProperty("username")
    private String username;

    @Column(unique = true, nullable = false)
    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    @JsonProperty("email")
    private String email;

    @Column(nullable = false)
    @NotBlank(message = "Password is required")
    @JsonProperty("password")
    private String password; // This will be encrypted

    @Column(name = "password_update_date")
    @JsonProperty("passwordUpdateDate")
    private LocalDateTime passwordUpdateDate;

    @Column(name = "password_token")
    @JsonProperty("passwordToken")
    private String passwordToken; // This will be encrypted

    @Column(name = "password_token_expiry")
    @JsonProperty("passwordTokenExpiry")
    private LocalDateTime passwordTokenExpiry;

    @Column(name = "is_active")
    @JsonProperty("isActive")
    private Boolean isActive = true;

    @Column(name = "created_at")
    @JsonProperty("createdAt")
    private LocalDateTime createdAt;

    @Column(name = "updated_at")
    @JsonProperty("updatedAt")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_date_time")
    @JsonProperty("lastLoginDateTime")
    private LocalDateTime lastLoginDateTime;

    @Column(name = "login_attempt")
    @JsonProperty("loginAttempt")
    private Integer loginAttempt = 0;

    @Column(name = "is_blocked")
    @JsonProperty("isBlocked")
    private Boolean isBlocked = false;

    @Column(name = "blocked_date")
    @JsonProperty("blockedDate")
    private LocalDateTime blockedDate;

    @Column(name = "is_mfa_enabled")
    @JsonProperty("isMfaEnabled")
    private Boolean isMfaEnabled = true;

    @PrePersist
    protected void onCreate() {
        createdAt = LocalDateTime.now();
        updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    // Constructors
    public User() {}

    @JsonCreator
    public User(@JsonProperty("username") String username, 
                @JsonProperty("email") String email, 
                @JsonProperty("password") String password) {
        this.username = username;
        this.email = email;
        this.password = password;
    }

    // UserDetails implementation
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptyList();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return !isBlocked;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return isActive;
    }

    // Getters and Setters
    public UUID getId() {
        return id;
    }

    public void setId(UUID id) {
        this.id = id;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public LocalDateTime getPasswordUpdateDate() {
        return passwordUpdateDate;
    }

    public void setPasswordUpdateDate(LocalDateTime passwordUpdateDate) {
        this.passwordUpdateDate = passwordUpdateDate;
    }

    public String getPasswordToken() {
        return passwordToken;
    }

    public void setPasswordToken(String passwordToken) {
        this.passwordToken = passwordToken;
    }

    public LocalDateTime getPasswordTokenExpiry() {
        return passwordTokenExpiry;
    }

    public void setPasswordTokenExpiry(LocalDateTime passwordTokenExpiry) {
        this.passwordTokenExpiry = passwordTokenExpiry;
    }

    public Boolean getIsActive() {
        return isActive;
    }

    public void setIsActive(Boolean isActive) {
        this.isActive = isActive;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }

    public LocalDateTime getLastLoginDateTime() {
        return lastLoginDateTime;
    }

    public void setLastLoginDateTime(LocalDateTime lastLoginDateTime) {
        this.lastLoginDateTime = lastLoginDateTime;
    }

    public Integer getLoginAttempt() {
        return loginAttempt;
    }

    public void setLoginAttempt(Integer loginAttempt) {
        this.loginAttempt = loginAttempt;
    }

    public Boolean getIsBlocked() {
        return isBlocked;
    }

    public void setIsBlocked(Boolean isBlocked) {
        this.isBlocked = isBlocked;
    }

    public LocalDateTime getBlockedDate() {
        return blockedDate;
    }

    public void setBlockedDate(LocalDateTime blockedDate) {
        this.blockedDate = blockedDate;
    }

    public Boolean getIsMfaEnabled() {
        return isMfaEnabled;
    }

    public void setIsMfaEnabled(Boolean isMfaEnabled) {
        this.isMfaEnabled = isMfaEnabled;
    }
}