package com.auth.controller;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HomeController {

    @GetMapping("/")
    @ResponseBody
    public String home() {
        return "Spring Authorization Server is running! " +
               "<br><br>Available endpoints:" +
               "<br>• <a href='/oauth2/authorize?response_type=code&client_id=auth-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid profile read'>Authorization URL</a>" +
               "<br>• <a href='/h2-console'>H2 Database Console</a>" +
               "<br>• <a href='/actuator/health'>Health Check</a>" +
               "<br>• <a href='/logout'>Logout</a>" +
               "<br>• POST /oauth2/token (Token endpoint)" +
               "<br>• GET /.well-known/openid-configuration (OpenID Configuration)";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping("/authorized")
    @ResponseBody
    public String authorized(Authentication authentication) {
        return "You have been successfully authorized! User: " + authentication.getName() +
               "<br><br><a href='/logout'>Logout</a>";
    }

    @GetMapping("/profile")
    @ResponseBody
    public String profile(Authentication authentication) {
        return "User Profile: " + authentication.getName() + 
               "<br>Authorities: " + authentication.getAuthorities() +
               "<br><br><a href='/logout'>Logout</a>";
    }

    @PostMapping("/logout")
    @ResponseBody
    public String logoutPost() {
        return "You have been logged out successfully!";
    }
}