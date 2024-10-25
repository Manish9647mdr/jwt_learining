package com.tkk.recruitment.controller;

import com.tkk.recruitment.model.MyUser;
import com.tkk.recruitment.repository.MyUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class RegistrationController {
    private final MyUserRepository myUserRepository;

    private final PasswordEncoder passwordEncoder;

    public RegistrationController(MyUserRepository myUserRepository, PasswordEncoder passwordEncoder) {
        this.myUserRepository = myUserRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @PostMapping("/register/user")
    public MyUser registerUser(@RequestBody MyUser user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return myUserRepository.save(user);
    }
}
