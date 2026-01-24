package com.bezbednost.sertifikat.controller;

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
}
