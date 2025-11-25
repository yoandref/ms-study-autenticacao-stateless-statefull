package io.github.devandref.ms_stateful_auth_api.core.service;

import io.github.devandref.ms_stateful_auth_api.core.dto.AuthRequest;
import io.github.devandref.ms_stateful_auth_api.core.dto.AuthUserResponse;
import io.github.devandref.ms_stateful_auth_api.core.dto.TokenDTO;
import io.github.devandref.ms_stateful_auth_api.core.model.User;
import io.github.devandref.ms_stateful_auth_api.core.repository.UserRepository;
import io.github.devandref.ms_stateful_auth_api.infra.exception.AuthenticationException;
import io.github.devandref.ms_stateful_auth_api.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public TokenDTO login(AuthRequest request) {
        var user = findByUsername(request.username());
        var accessToken = tokenService.createToken(user.getUsername());
        validatePassword(request.password(), user.getPassword());
        return new TokenDTO(accessToken);
    }

    public TokenDTO validateToken(String accessToken) {
        validateExistingToken(accessToken);
        var valid = tokenService.validateAccessToken(accessToken);
        if(valid) {
            return new TokenDTO(accessToken);
        }
        throw new AuthenticationException("Invalid token!");
    }

    public AuthUserResponse getAuthenticateUser(String accessToken) {
        var tokenData = tokenService.getTokenData(accessToken);
        var user = findByUsername(tokenData.username());
        return new AuthUserResponse(user.getId(), user.getUsername());
    }

    public void logout(String accessToken) {
        tokenService.deleteRedisToken(accessToken);
    }

    private void validatePassword(String rawPassword, String encodedPassword) {
        if (isEmpty(rawPassword)) {
            throw new ValidationException("A senha precisa ser informada.");
        }

        if (!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new ValidationException("A senha informada está incorreta!");
        }
    }

    private void validateExistingToken(String accessToken) {
        if (isEmpty(accessToken)) {
            throw new ValidationException("O token de acesso deve ser informado!");
        }
    }

    private User findByUsername(String username) {
        return userRepository.findByUsername(username).orElseThrow(() -> new ValidationException("User not found!"));
    }

}
