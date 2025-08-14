package com.auth.config;

import com.auth.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

@Component
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserService userService;

    @Override
    public void run(String... args) throws Exception {
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
}