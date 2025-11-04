package io.github.devandref.ms_stateless_auth_api.core.service;

import io.github.devandref.ms_stateless_auth_api.core.dto.AuthRequestDto;
import io.github.devandref.ms_stateless_auth_api.core.dto.TokenDto;
import io.github.devandref.ms_stateless_auth_api.core.repository.UserRepository;
import io.github.devandref.ms_stateless_auth_api.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final JWTService jwtService;

    public TokenDto login(AuthRequestDto authRequestDto) {
        var user = userRepository.findByUsername(authRequestDto.username())
                .orElseThrow(() -> new ValidationException("User not found!"));
        var accessToken = jwtService.createToken(user);
        validatePassword(authRequestDto.password(), user.getPassword());
        return new TokenDto(accessToken);
    }

    private void validatePassword(String rawPassword, String encodedPassword) {
        if(!passwordEncoder.matches(rawPassword, encodedPassword)) {
            throw new ValidationException("A senha informada está incorreta!");
        }
    }

    public TokenDto validateToken(String accessToken) {
        validateExistingToken(accessToken);
        jwtService.validateAccessToken(accessToken);
        return new TokenDto(accessToken);
    }

    private void validateExistingToken(String accessToken) {
        if(isEmpty(accessToken)) {
            throw new ValidationException("O token de acesso deve ser informado!");
        }
    }


}
