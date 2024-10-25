package com.tkk.recruitment.controller;

import com.tkk.recruitment.service.MyUserDetailService;
import com.tkk.recruitment.webtoken.JwtService;
import com.tkk.recruitment.webtoken.LoginForm;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ContentController {

    private final AuthenticationManager authenticationManager;

    private final JwtService jwtService;

    private final MyUserDetailService myUserDetailService;

    public ContentController(AuthenticationManager authenticationManager, JwtService jwtService, MyUserDetailService myUserDetailService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.myUserDetailService = myUserDetailService;
    }

    @GetMapping("/home")
    public String handleWelcome() {
//        return "home";
        return "Welcome to home";
    }

    @GetMapping("/admin/home")
    public String handleAdminHome() {
//        return "home_admin";
        return "Welcome to ADMIN Home";
    }

    @GetMapping("/user/home")
    public String handleUserHome() {
//        return "home_user";
        return "Welcome to User Home";
    }

    @PostMapping("/authenticate")
    public ResponseEntity<String> authenticateAndGetToken(@RequestBody LoginForm loginForm) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
                loginForm.username(), loginForm.password()
        ));
        if (authentication.isAuthenticated()) {
            String token = jwtService.generateToken(myUserDetailService.loadUserByUsername(loginForm.username()));
            return ResponseEntity.ok(token); // Return the token in the response body
        } else {
            throw new UsernameNotFoundException("Invalid credentials");
        }
    }
}
