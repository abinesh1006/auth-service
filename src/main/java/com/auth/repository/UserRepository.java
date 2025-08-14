package com.auth.repository;

import com.auth.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    Optional<User> findByUsername(String username);
    
    Optional<User> findByEmail(String email);
    
    Optional<User> findByUsernameOrEmail(String username, String email);
    
    boolean existsByUsername(String username);
    
    boolean existsByEmail(String email);
    
    @Modifying
    @Query("UPDATE User u SET u.lastLoginDateTime = :loginTime WHERE u.id = :userId")
    void updateLastLoginDateTime(@Param("userId") UUID userId, @Param("loginTime") LocalDateTime loginTime);
    
    @Modifying
    @Query("UPDATE User u SET u.loginAttempt = :attempts WHERE u.id = :userId")
    void updateLoginAttempts(@Param("userId") UUID userId, @Param("attempts") Integer attempts);
    
    @Modifying
    @Query("UPDATE User u SET u.isBlocked = :blocked, u.blockedDate = :blockedDate WHERE u.id = :userId")
    void updateBlockStatus(@Param("userId") UUID userId, @Param("blocked") Boolean blocked, @Param("blockedDate") LocalDateTime blockedDate);
    
    @Modifying
    @Query("UPDATE User u SET u.passwordToken = :token, u.passwordTokenExpiry = :expiry WHERE u.id = :userId")
    void updatePasswordToken(@Param("userId") UUID userId, @Param("token") String token, @Param("expiry") LocalDateTime expiry);
}