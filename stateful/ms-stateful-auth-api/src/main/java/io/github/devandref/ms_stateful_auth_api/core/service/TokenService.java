package io.github.devandref.ms_stateful_auth_api.core.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.devandref.ms_stateful_auth_api.core.dto.TokenData;
import io.github.devandref.ms_stateful_auth_api.infra.exception.AuthenticationException;
import io.github.devandref.ms_stateful_auth_api.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.apache.commons.lang3.StringUtils;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class TokenService {

    private static final Integer TOKEN_INDEX = 1;
    private static final Long ONE_DAY_IN_SECONDS = 86400L;

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public String createToken(String username) {
        var accessToken = UUID.randomUUID().toString();
        var data = new TokenData(username);
        var jsonData = getJsonData(data);
        redisTemplate.opsForValue().set(accessToken, jsonData);
        redisTemplate.expireAt(accessToken, Instant.now().plusSeconds(ONE_DAY_IN_SECONDS));
        return accessToken;
    }

    private String getJsonData(Object payload) {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception ex) {
            return "";
        }
    }

    public TokenData getTokenData(String token) {
        var accessToken = extractToken(token);
        var jsonString = getRedisTokenValue(accessToken);

        try {
            return objectMapper.readValue(jsonString, TokenData.class);
        } catch (Exception exception) {
            throw new AuthenticationException("Error " + exception.getMessage());
        }
    }

    public Boolean validateAccessToken(String token) {
        var accessToken = extractToken(token);
        var data = getRedisTokenValue(accessToken);
        return !isEmpty(data);
    }

    private String getRedisTokenValue(String token) {
        return redisTemplate.opsForValue().get(token);
    }


    public void deleteRedisToken(String token) {
        var accessToken = extractToken(token);
        redisTemplate.delete(accessToken);
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
