package com.auth.controller;

import com.auth.service.LogoutService;
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
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RequestParam;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;

@Controller
@Tag(name = "Home & Authentication", description = "Main application endpoints and authentication flow")
public class HomeController {

    @Autowired
    private LogoutService logoutService;

    @Operation(
        summary = "Get application information",
        description = "Returns the home page with available endpoints and application status"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Success", 
                    content = @Content(mediaType = "text/html", 
                    examples = @ExampleObject(value = "Spring Authorization Server is running! Available endpoints...")))
    })
    @GetMapping("/")
    @ResponseBody
    public String home() {
        return "Spring Authorization Server is running! " +
               "<br><br>Available endpoints:" +
               "<br>• <a href='/oauth2/authorize?response_type=code&client_id=auth-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid profile read'>Authorization URL</a>" +
               "<br>• <a href='/h2-console'>H2 Database Console</a>" +
               "<br>• <a href='/actuator/health'>Health Check</a>" +
               "<br>• <a href='/logout'>Logout</a>" +
               "<br>• <a href='/swagger-ui/index.html'>Swagger UI</a>" +
               "<br>• POST /oauth2/token (Token endpoint)" +
               "<br>• GET /.well-known/openid-configuration (OpenID Configuration)";
    }

    @Operation(
        summary = "Login page",
        description = "Display the login form for user authentication"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Login page displayed successfully")
    })
    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @Operation(
        summary = "Authorization success page",
        description = "Page displayed after successful OAuth2 authorization"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Authorization successful", 
                    content = @Content(mediaType = "text/html"))
    })
    @GetMapping("/authorized")
    @ResponseBody
    public String authorized(
        @Parameter(description = "Authenticated user information", hidden = true) 
        Authentication authentication) {
        return "You have been successfully authorized! User: " + authentication.getName() +
               "<br><br><a href='/logout'>Logout</a>";
    }

    @Operation(
        summary = "User profile information",
        description = "Display authenticated user's profile and authorities"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Profile information retrieved successfully", 
                    content = @Content(mediaType = "text/html")),
        @ApiResponse(responseCode = "401", description = "Unauthorized")
    })
    @GetMapping("/profile")
    @ResponseBody
    public String profile(
        @Parameter(description = "Authenticated user information", hidden = true) 
        Authentication authentication) {
        return "User Profile: " + authentication.getName() + 
               "<br>Authorities: " + authentication.getAuthorities() +
               "<br><br><a href='/logout'>Logout</a>";
    }

    @Operation(
        summary = "User logout",
        description = "Logout user and revoke all OAuth2 tokens from database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "302", description = "Logout successful, redirecting to login page"),
        @ApiResponse(responseCode = "401", description = "User not authenticated")
    })
    @PostMapping("/logout")
    public String logoutPost(
        @Parameter(description = "Authenticated user information", hidden = true) 
        Authentication authentication, 
        @Parameter(description = "HTTP request", hidden = true) 
        HttpServletRequest request, 
        @Parameter(description = "HTTP response", hidden = true) 
        HttpServletResponse response) {
        if (authentication != null) {
            // Perform complete OAuth2 token cleanup from database
            logoutService.performCompleteLogout(authentication);
            
            // Perform standard Spring Security logout
            new SecurityContextLogoutHandler().logout(request, response, authentication);
        }
        
        return "redirect:/login?logout";
    }

    @Operation(
        summary = "API logout",
        description = "Logout user via API and revoke all OAuth2 tokens from database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Logout successful", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = "{\"message\": \"Successfully logged out and all tokens revoked\", \"status\": \"success\"}"))),
        @ApiResponse(responseCode = "200", description = "No active session", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = "{\"message\": \"No active session found\", \"status\": \"error\"}")))
    })
    @PostMapping("/api/logout")
    @ResponseBody
    public String apiLogout(
        @Parameter(description = "Authenticated user information", hidden = true) 
        Authentication authentication, 
        @Parameter(description = "HTTP request", hidden = true) 
        HttpServletRequest request, 
        @Parameter(description = "HTTP response", hidden = true) 
        HttpServletResponse response) {
        if (authentication != null) {
            // Perform complete OAuth2 token cleanup from database
            logoutService.performCompleteLogout(authentication);
            
            // Perform standard Spring Security logout
            new SecurityContextLogoutHandler().logout(request, response, authentication);
            
            return "{\"message\": \"Successfully logged out and all tokens revoked\", \"status\": \"success\"}";
        }
        
        return "{\"message\": \"No active session found\", \"status\": \"error\"}";
    }

    @Operation(
        summary = "Revoke specific token",
        description = "Revoke a specific OAuth2 token from the database"
    )
    @ApiResponses(value = {
        @ApiResponse(responseCode = "200", description = "Token revocation result", 
                    content = @Content(mediaType = "application/json",
                    examples = {
                        @ExampleObject(name = "Success", value = "{\"message\": \"Token successfully revoked\", \"status\": \"success\"}"),
                        @ExampleObject(name = "Not Found", value = "{\"message\": \"Token not found or already revoked\", \"status\": \"error\"}")
                    })),
        @ApiResponse(responseCode = "401", description = "Unauthorized", 
                    content = @Content(mediaType = "application/json",
                    examples = @ExampleObject(value = "{\"message\": \"Unauthorized\", \"status\": \"error\"}")))
    })
    @PostMapping("/api/revoke-token")
    @ResponseBody
    public String revokeToken(
        @Parameter(description = "Token to revoke", required = true, example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...")
        @RequestParam String token, 
        @Parameter(description = "Authenticated user information", hidden = true) 
        Authentication authentication) {
        if (authentication != null) {
            boolean revoked = logoutService.revokeToken(token);
            if (revoked) {
                return "{\"message\": \"Token successfully revoked\", \"status\": \"success\"}";
            } else {
                return "{\"message\": \"Token not found or already revoked\", \"status\": \"error\"}";
            }
        }
        
        return "{\"message\": \"Unauthorized\", \"status\": \"error\"}";
    }
}