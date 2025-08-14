package com.auth.service;

import com.auth.entity.User;
import com.auth.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@Transactional
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));
        
        return user;
    }

    public void updateLastLogin(String usernameOrEmail) {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with username or email: " + usernameOrEmail));
        
        userRepository.updateLastLoginDateTime(user.getId(), LocalDateTime.now());
    }

    public void incrementLoginAttempts(String usernameOrEmail) {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElse(null);
        
        if (user != null) {
            int attempts = user.getLoginAttempt() + 1;
            userRepository.updateLoginAttempts(user.getId(), attempts);
            
            // Block user after 5 failed attempts
            if (attempts >= 5) {
                userRepository.updateBlockStatus(user.getId(), true, LocalDateTime.now());
            }
        }
    }

    public void resetLoginAttempts(String usernameOrEmail) {
        User user = userRepository.findByUsernameOrEmail(usernameOrEmail, usernameOrEmail)
                .orElse(null);
        
        if (user != null) {
            userRepository.updateLoginAttempts(user.getId(), 0);
        }
    }
}