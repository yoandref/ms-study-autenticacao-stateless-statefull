package io.github.devandref.ms_stateful_auth_api.core.controller;

import io.github.devandref.ms_stateful_auth_api.core.dto.AuthRequest;
import io.github.devandref.ms_stateful_auth_api.core.dto.AuthUserResponse;
import io.github.devandref.ms_stateful_auth_api.core.dto.TokenDTO;
import io.github.devandref.ms_stateful_auth_api.core.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RestController
@RequestMapping("api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("login")
    public TokenDTO login(@RequestBody AuthRequest authRequest) {
        return authService.login(authRequest);
    }

    @PostMapping("token/validate")
    public TokenDTO login(@RequestHeader String accessToken) {
        return authService.validateToken(accessToken);
    }

    @PostMapping("logout")
    public HashMap<String, Object> logout(@RequestHeader String accessToken) {
        authService.logout(accessToken);
        var response = new HashMap<String, Object>();
        var ok = HttpStatus.OK;
        response.put("status", ok.name());
        response.put("code", ok.value());
        return response;
    }

    @GetMapping("user")
    public AuthUserResponse getAuthenticatedUser(@RequestHeader String accessToken) {
        return authService.getAuthenticateUser(accessToken);
    }

}
