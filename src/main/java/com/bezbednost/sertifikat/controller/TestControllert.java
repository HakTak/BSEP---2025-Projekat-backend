package com.bezbednost.sertifikat.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class TestControllert {

    @GetMapping("/hello")
    public String sayHello() {
        return "Pozdrav iz HTTPS Spring Boot aplikacije!";
    }
    @GetMapping("/demo")
    @PreAuthorize("isAuthenticated()") // Samo proverava da li je korisnik ulogovan (ima validan token)
    public String demo() {
        return "Pozdrav! Ako ovo vidiš, tvoj token je validan.";
    }

    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('ADMIN')") // SAMO korisnici sa ulogom ADMIN mogu pristupiti
    public String adminOnly() {
        return "Dobrodošao, ADMIN! Ovo je tajna zona.";
    }

    @GetMapping("/user-or-admin")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')") // Korisnici sa ulogom USER ili ADMIN
    public String userOrAdmin() {
        return "Dobrodošao, ulogovani korisniče!";
    }
}
