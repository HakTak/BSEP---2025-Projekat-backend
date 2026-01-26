package com.bezbednost.sertifikat.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.Contact;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("BSEP Sertifikat API")
                        .version("1.0.0")
                        .description("Backend API za upravljanje sertifikatima")
                        .contact(new Contact()
                                .name("BSEP Tim")
                                .email("info@bsep.rs")));
    }
}
