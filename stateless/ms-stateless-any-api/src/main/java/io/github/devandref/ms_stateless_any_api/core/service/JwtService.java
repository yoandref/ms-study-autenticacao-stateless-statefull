package io.github.devandref.ms_stateless_any_api.core.service;

import io.github.devandref.ms_stateless_any_api.core.dto.AuthUserResponse;
import io.github.devandref.ms_stateless_any_api.exception.AuthenticationException;
import io.github.devandref.ms_stateless_any_api.exception.ValidationException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;

@Service
public class JwtService {

    private static final Integer TOKEN_INDEX = 1;

    @Value("${app.token.secret-key}")
    private String secretKey;

    public AuthUserResponse getAuthenticatedUser(String token) {
        var tokenClaims = getClaims(token);
        var userId = Integer.valueOf((String) tokenClaims.get("id"));
        return new AuthUserResponse(userId, (String) tokenClaims.get("username"));
    }

    public void validateAccessToken(String token) {
        getClaims(token);
    }

    private Claims getClaims(String token) {
        var accessToken = extractToken(token);
        try {
            return Jwts
                    .parserBuilder()
                    .setSigningKey(generateSign())
                    .build()
                    .parseClaimsJws(accessToken)
                    .getBody();
        } catch (Exception ex) {
            throw new AuthenticationException("Invalid token " + ex.getMessage());
        }
    }

    private SecretKey generateSign() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    private String extractToken(String token) {
        if (StringUtils.isEmpty(token)) {
            throw new ValidationException("O token de acesso não foi informado.");
        }

        if (token.contains(StringUtils.SPACE)) {
            return token.split(StringUtils.SPACE)[TOKEN_INDEX];
        }
        return token;
    }

}
