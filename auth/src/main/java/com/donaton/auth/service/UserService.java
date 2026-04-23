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

    public User guardar(User user) {
        return repository.save(user);
    }

    public List<User> listar() {
        return repository.findAll();
    }
}