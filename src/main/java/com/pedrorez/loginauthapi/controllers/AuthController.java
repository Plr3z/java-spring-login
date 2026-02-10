package com.pedrorez.loginauthapi.controllers;

import com.pedrorez.loginauthapi.domain.user.UserEntity;
import com.pedrorez.loginauthapi.dto.LoginRequestDTO;
import com.pedrorez.loginauthapi.dto.LoginAndRegisterResponseDTO;
import com.pedrorez.loginauthapi.dto.RegisterRequestDTO;
import com.pedrorez.loginauthapi.infra.security.TokenService;
import com.pedrorez.loginauthapi.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity<LoginAndRegisterResponseDTO> login(@RequestBody LoginRequestDTO body){
        UserEntity user = this.userRepository.findByEmail(body.email()).orElseThrow(() -> new UsernameNotFoundException("User not found"));
        if(passwordEncoder.matches(body.password(), user.getPassword())){
            String token = this.tokenService.create(user);
            return ResponseEntity.ok(new LoginAndRegisterResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }

    @PostMapping("/register")
    public ResponseEntity<LoginAndRegisterResponseDTO> register(@RequestBody RegisterRequestDTO body){
        Optional<UserEntity> user = this.userRepository.findByEmail(body.email());

        if(user.isEmpty()){
            UserEntity newUser = new UserEntity();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());

            this.userRepository.save(newUser);

            String token = this.tokenService.create(newUser);
            return ResponseEntity.ok(new LoginAndRegisterResponseDTO(newUser.getName(), token));
        }

        return ResponseEntity.badRequest().build();
    }
}
