package com.auth.controller;

import com.auth.entity.User;
import com.auth.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/users")
@Tag(name = "User Management", description = "User CRUD operations and management endpoints")
public class UserController {

    @Autowired
    private UserService userService;

    @Operation(
        summary = "Get all users",
        description = "Retrieve a list of all users in the system. Requires ADMIN role."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Users retrieved successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        [
                          {
                            "id": "550e8400-e29b-41d4-a716-446655440000",
                            "username": "user123",
                            "email": "user@example.com",
                            "enabled": true,
                            "accountNonExpired": true,
                            "accountNonLocked": true,
                            "credentialsNonExpired": true,
                            "authorities": ["ROLE_USER"]
                          }
                        ]"""))),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {
        List<User> users = userService.findAllUsers();
        return ResponseEntity.ok(users);
    }

    @Operation(
        summary = "Get user by ID",
        description = "Retrieve a specific user by their ID. Users can access their own data, admins can access any user."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User found", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "id": "550e8400-e29b-41d4-a716-446655440000",
                          "username": "user123",
                          "email": "user@example.com",
                          "enabled": true,
                          "accountNonExpired": true,
                          "accountNonLocked": true,
                          "credentialsNonExpired": true,
                          "authorities": ["ROLE_USER"]
                        }"""))),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @GetMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    public ResponseEntity<User> getUserById(
        @Parameter(description = "User ID", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
        @PathVariable UUID id) {
        return userService.findById(id)
                .map(user -> ResponseEntity.ok(user))
                .orElse(ResponseEntity.notFound().build());
    }

    @Operation(
        summary = "Create new user",
        description = "Create a new user account. Requires ADMIN role."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "201", description = "User created successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "id": "550e8400-e29b-41d4-a716-446655440000",
                          "username": "newuser",
                          "email": "newuser@example.com",
                          "enabled": true,
                          "accountNonExpired": true,
                          "accountNonLocked": true,
                          "credentialsNonExpired": true,
                          "authorities": ["ROLE_USER"]
                        }"""))),
        @ApiResponse(responseCode = "400", description = "Invalid request data or user already exists"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> createUser(
        @Parameter(description = "User creation request", required = true)
        @RequestBody CreateUserRequest request) {
        try {
            User user = userService.createUser(request.getUsername(), request.getEmail(), request.getPassword());
            return ResponseEntity.status(HttpStatus.CREATED).body(user);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @Operation(
        summary = "Update user",
        description = "Update user information. Users can update their own data, admins can update any user."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User updated successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = """
                        {
                          "id": "550e8400-e29b-41d4-a716-446655440000",
                          "username": "updateduser",
                          "email": "updated@example.com",
                          "enabled": true,
                          "accountNonExpired": true,
                          "accountNonLocked": true,
                          "credentialsNonExpired": true,
                          "authorities": ["ROLE_USER"]
                        }"""))),
        @ApiResponse(responseCode = "400", description = "Invalid request data"),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PutMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    public ResponseEntity<?> updateUser(
        @Parameter(description = "User ID", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
        @PathVariable UUID id, 
        @Parameter(description = "Updated user data", required = true)
        @RequestBody User updatedUser) {
        try {
            User user = userService.updateUser(id, updatedUser);
            return ResponseEntity.ok(user);
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @Operation(
        summary = "Delete user",
        description = "Delete a user account. Requires ADMIN role."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "204", description = "User deleted successfully"),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> deleteUser(
        @Parameter(description = "User ID", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
        @PathVariable UUID id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @Operation(
        summary = "Block user",
        description = "Block a user account, preventing them from logging in. Requires ADMIN role."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User blocked successfully"),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/{id}/block")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> blockUser(
        @Parameter(description = "User ID", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
        @PathVariable UUID id) {
        userService.blockUser(id);
        return ResponseEntity.ok().build();
    }

    @Operation(
        summary = "Unblock user",
        description = "Unblock a previously blocked user account. Requires ADMIN role."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "User unblocked successfully"),
        @ApiResponse(responseCode = "404", description = "User not found"),
        @ApiResponse(responseCode = "403", description = "Access denied - Admin role required")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/{id}/unblock")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> unblockUser(
        @Parameter(description = "User ID", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
        @PathVariable UUID id) {
        userService.unblockUser(id);
        return ResponseEntity.ok().build();
    }

    @Operation(
        summary = "Change user password",
        description = "Change password for a user. Users can change their own password, admins can change any user's password."
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Password changed successfully", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = "\"Password changed successfully\""))),
        @ApiResponse(responseCode = "400", description = "Invalid password or user not found"),
        @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PostMapping("/{id}/change-password")
    @PreAuthorize("hasRole('ADMIN') or #id == authentication.principal.id")
    public ResponseEntity<?> changePassword(
        @Parameter(description = "User ID", required = true, example = "550e8400-e29b-41d4-a716-446655440000")
        @PathVariable UUID id, 
        @Parameter(description = "Password change request", required = true)
        @RequestBody ChangePasswordRequest request) {
        try {
            userService.changePassword(id, request.getNewPassword());
            return ResponseEntity.ok().body("Password changed successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    // DTOs
    @Schema(description = "Request object for creating a new user")
    public static class CreateUserRequest {
        @Schema(description = "Username for the new user", example = "newuser", required = true)
        private String username;
        
        @Schema(description = "Email address for the new user", example = "newuser@example.com", required = true)
        private String email;
        
        @Schema(description = "Password for the new user", example = "SecurePassword123!", required = true)
        private String password;

        // Getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getEmail() { return email; }
        public void setEmail(String email) { this.email = email; }
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }

    @Schema(description = "Request object for changing user password")
    public static class ChangePasswordRequest {
        @Schema(description = "New password for the user", example = "NewSecurePassword123!", required = true)
        private String newPassword;

        // Getters and setters
        public String getNewPassword() { return newPassword; }
        public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
    }
}