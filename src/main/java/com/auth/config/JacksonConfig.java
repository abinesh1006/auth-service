package com.auth.config;

import com.auth.entity.User;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;

import java.util.List;

@Configuration
public class JacksonConfig {

    @Bean
    public ObjectMapper objectMapper() {
        ObjectMapper mapper = new ObjectMapper();
        
        // Register Spring Security modules
        ClassLoader classLoader = getClass().getClassLoader();
        List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
        mapper.registerModules(securityModules);
        
        // Register OAuth2 Authorization Server module
        mapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
        
        // Add mixin for User entity
        mapper.addMixIn(User.class, UserMixin.class);
        
        return mapper;
    }

    @JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)
    @JsonAutoDetect(fieldVisibility = JsonAutoDetect.Visibility.ANY, 
                    getterVisibility = JsonAutoDetect.Visibility.NONE,
                    isGetterVisibility = JsonAutoDetect.Visibility.NONE)
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static abstract class UserMixin {
        
        @JsonCreator
        public UserMixin(@JsonProperty("username") String username,
                        @JsonProperty("email") String email,
                        @JsonProperty("password") String password) {
        }
    }
}