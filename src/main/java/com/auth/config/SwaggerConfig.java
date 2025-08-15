package com.auth.config;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;

@Configuration
public class SwaggerConfig {

    // ✅ Applies security schemes to ALL OpenAPI groups
    @Bean
    public OpenApiCustomizer securityOpenApiCustomiser() {
        return openApi -> openApi
            .addSecurityItem(new SecurityRequirement().addList("Bearer Authentication"))
            .addSecurityItem(new SecurityRequirement().addList("OAuth2"))
            .components(new Components()
                .addSecuritySchemes("Bearer Authentication",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")
                        .description("JWT token obtained from OAuth2 flow"))
                .addSecuritySchemes("OAuth2",
                    new SecurityScheme()
                        .type(SecurityScheme.Type.OAUTH2)
                        .description("OAuth2 Authorization Code Flow")
                        .flows(new io.swagger.v3.oas.models.security.OAuthFlows()
                            .authorizationCode(new io.swagger.v3.oas.models.security.OAuthFlow()
                                .authorizationUrl("/oauth2/authorize")
                                .tokenUrl("/oauth2/token")
                                .refreshUrl("/oauth2/token")
                                .scopes(new io.swagger.v3.oas.models.security.Scopes()
                                    .addString("openid", "OpenID Connect")
                                    .addString("profile", "User profile information")
                                    .addString("read", "Read access")
                                    .addString("write", "Write access"))))));
    }

    // ✅ Base info applies to all groups too
    @Bean
    public OpenAPI baseOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Spring Authorization Server API")
                .description("OAuth2 Authorization Server with JWT Token Management")
                .version("1.0.0")
                .contact(new Contact()
                    .name("Auth Service Team")
                    .email("auth@example.com"))
                .license(new License()
                    .name("MIT License")
                    .url("https://opensource.org/licenses/MIT")));
    }
}
