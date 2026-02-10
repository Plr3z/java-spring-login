package com.pedrorez.loginauthapi.controllers;

import com.auth0.jwt.JWT;
import com.pedrorez.loginauthapi.domain.user.UserEntity;
import com.pedrorez.loginauthapi.infra.security.TokenService;
import com.pedrorez.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;
    private final TokenService tokenService;

    @GetMapping
    public ResponseEntity<UserEntity> getUser(@RequestHeader("Authorization") String token){
        token = token.replace("Bearer ", "");
        var email = this.tokenService.validateToken(token);
        UserEntity user = this.userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return ResponseEntity.ok(user);
    }
}
