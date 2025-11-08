package io.github.devandref.ms_stateless_auth_api.core.controller;

import io.github.devandref.ms_stateless_auth_api.core.dto.AuthRequestDto;
import io.github.devandref.ms_stateless_auth_api.core.dto.TokenDto;
import io.github.devandref.ms_stateless_auth_api.core.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@AllArgsConstructor
@RequestMapping("api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("login")
    public TokenDto login(@RequestBody AuthRequestDto authRequestDto) {
        return authService.login(authRequestDto);
    }

    @PostMapping("token/validate")
    public TokenDto login(@RequestHeader String accessToken) {
        return authService.validateToken(accessToken);
    }

}
