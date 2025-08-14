package com.auth.service;

import com.auth.entity.User;
import com.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@Transactional
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public User createUser(String username, String email, String password) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists: " + username);
        }
        
        if (userRepository.existsByEmail(email)) {
            throw new RuntimeException("Email already exists: " + email);
        }

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setPasswordUpdateDate(LocalDateTime.now());
        user.setIsActive(true);
        user.setLoginAttempt(0);
        user.setIsBlocked(false);
        user.setIsMfaEnabled(true);

        return userRepository.save(user);
    }

    public Optional<User> findById(UUID id) {
        return userRepository.findById(id);
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public List<User> findAllUsers() {
        return userRepository.findAll();
    }

    public User updateUser(UUID id, User updatedUser) {
        return userRepository.findById(id)
                .map(user -> {
                    user.setUsername(updatedUser.getUsername());
                    user.setEmail(updatedUser.getEmail());
                    user.setIsActive(updatedUser.getIsActive());
                    user.setIsMfaEnabled(updatedUser.getIsMfaEnabled());
                    return userRepository.save(user);
                })
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
    }

    public void deleteUser(UUID id) {
        userRepository.deleteById(id);
    }

    public void changePassword(UUID id, String newPassword) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id: " + id));
        
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setPasswordUpdateDate(LocalDateTime.now());
        userRepository.save(user);
    }

    public void blockUser(UUID id) {
        userRepository.updateBlockStatus(id, true, LocalDateTime.now());
    }

    public void unblockUser(UUID id) {
        userRepository.updateBlockStatus(id, false, null);
        userRepository.updateLoginAttempts(id, 0);
    }

    public void generatePasswordResetToken(UUID id, String token, LocalDateTime expiry) {
        userRepository.updatePasswordToken(id, passwordEncoder.encode(token), expiry);
    }

    public boolean validatePasswordResetToken(UUID id, String token) {
        User user = userRepository.findById(id).orElse(null);
        if (user == null || user.getPasswordToken() == null || user.getPasswordTokenExpiry() == null) {
            return false;
        }
        
        if (LocalDateTime.now().isAfter(user.getPasswordTokenExpiry())) {
            return false;
        }
        
        return passwordEncoder.matches(token, user.getPasswordToken());
    }
}