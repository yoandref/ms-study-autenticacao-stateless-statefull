package io.github.devandref.ms_stateless_auth_api.core.service;

import io.github.devandref.ms_stateless_auth_api.core.model.User;
import io.github.devandref.ms_stateless_auth_api.infra.exception.AuthenticationException;
import io.github.devandref.ms_stateless_auth_api.infra.exception.ValidationException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class JWTService {

    @Value("${app.token.secret-key}")
    private String secretKey;

    private static final Integer TOKEN_INDEX = 1;
    private static final Integer ONE_DAY_IN_HOURS = 24;

    public String createToken(User user) {
        var data = new HashMap<String, String>();
        data.put("id", user.getId().toString());
        data.put("username", user.getUsername());
        return Jwts
                .builder()
                .setClaims(data)
                .setExpiration(genereteExpiresAt())
                .signWith(generateSign())
                .compact();

    }

    public void validateAccessToken(String token) {
        var accessToken = extractToken(token);
        try {
            Jwts
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

    private Date genereteExpiresAt() {
        return Date.from(LocalDateTime.now().plusHours(ONE_DAY_IN_HOURS).atZone(ZoneId.systemDefault()).toInstant());
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
