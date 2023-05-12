package io.springsecurity.jwt.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
public class JwtTokenUtils {

    @Value("${jwt.token.secret}")
    private String secretKey;
    private final Long expireTimeNs = 1000 * 60 * 60L;

    public String createToken(String userName) {

        Claims claims = Jwts.claims(); // 일종의 map
        claims.put("userName", userName);

        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + expireTimeNs))
                .signWith(stringToKey(secretKey), SignatureAlgorithm.HS256)
                .compact();

    }

    private Key stringToKey(String secretKey) {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

}
