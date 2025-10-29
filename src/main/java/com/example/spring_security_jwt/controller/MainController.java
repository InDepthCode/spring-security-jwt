package com.example.spring_security_jwt.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class MainController {

    @GetMapping("/welcome")
    public String welcome() {
        return "Everyone access: Welcome to Spring Security JWT";
    }

    @GetMapping("/user")
    public String user() {
        return "User Content with JWT";
    }
}
