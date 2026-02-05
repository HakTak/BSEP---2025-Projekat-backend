package com.bezbednost.sertifikat.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestControllert {

    @GetMapping("/hello")
    public String sayHello() {
        return "Pozdrav iz HTTPS Spring Boot aplikacije!";
    }

    @GetMapping("/demo")
    @PreAuthorize("isAuthenticated()")
    public String demo() {
        return "Pozdrav! Ako ovo vidiš, tvoj token je validan.";
    }

    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('ADMIN')") // Pazi: Spring često traži "ROLE_ADMIN", proveri svoj konverter
    public String adminOnly() {
        return "Dobrodošao, ADMIN! Ovo je tajna zona.";
    }

}
