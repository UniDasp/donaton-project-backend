package com.donaton.auth.service;

import com.donaton.auth.model.User;
import com.donaton.auth.repository.UserRepository;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {

    private final UserRepository repository;

    public UserService(UserRepository repository) {
        this.repository = repository;
    }

    public User registrar(User user) {
        return repository.save(user);
    }

    public User login(String email, String password) {

        User user = repository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        if (!user.getPassword().equals(password)) {
            throw new RuntimeException("Contraseña incorrecta");
        }

        return user;
    }
}