package com.smapp.gateway.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import org.springframework.context.annotation.Configuration;

@Configuration
@OpenAPIDefinition(
        info = @Info(
                title = "smApp Cloud API Gateway",
                version = "1.0.0",
                description = "Central Entry Point & Security Gateway for Social Media Microservices Platform",
                contact = @Contact(name = "smApp DevOps & Security", email = "gateway@smapp.com")
        ),
        security = @SecurityRequirement(name = "bearerAuth"),
        servers = {
                @Server(url = "http://localhost:8080", description = "Local Gateway Server")
        }
)
@SecurityScheme(
        name = "bearerAuth",
        type = SecuritySchemeType.HTTP,
        scheme = "bearer",
        bearerFormat = "JWT",
        description = "Enter JWT Bearer token obtained from /api/auth/login"
)
public class OpenApiConfig {
}
