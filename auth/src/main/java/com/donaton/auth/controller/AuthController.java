package com.donaton.auth.controller;

import com.donaton.auth.dto.AuthDTO;
import com.donaton.auth.model.User;
import com.donaton.auth.service.UserService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final UserService service;

    public AuthController(UserService service) {
        this.service = service;
    }

    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return service.registrar(user);
    }

    @PostMapping("/login")
    public String login(@RequestBody AuthDTO dto) {
        User user = service.login(dto.getEmail(), dto.getPassword());

        return "Login correcto: " + user.getEmail();
    }
}