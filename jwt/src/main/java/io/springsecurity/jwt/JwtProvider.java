package io.springsecurity.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.springsecurity.jwt.service.UserContext;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final UserDetailsService userDetailsService;

    @Value("${jwt.token.secret}")
    private String secretKey;
    private final Long expireTimeNs = 1000 * 60 * 60L;


    // AccessToken 발급
    public String createToken(Authentication authentication) {

        Claims claims = Jwts.claims(); // 일종의 map
        claims.put("roles", authentication.getAuthorities());
        claims.setIssuedAt(new Date(System.currentTimeMillis()));
        claims.setExpiration(new Date(System.currentTimeMillis() + expireTimeNs));

        return Jwts.builder()
                .setHeaderParam(Header.TYPE, Header.JWT_TYPE)
                .setClaims(claims)
                .setSubject(authentication.getName())
                .signWith(stringToKey(secretKey), SignatureAlgorithm.HS256)
                .compact();
    }

    // secret key 를 바이트코드로 변경, 시그니처에 Hmac Sha 256 알고리즘 적용
    private Key stringToKey(String secretKey) {
        return Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    // token 검증 - Authorization 에 사용

    public boolean validateToken(String jwt) {

        try {
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(stringToKey(secretKey))
                    .build()
                    .parseClaimsJws(jwt).getBody();

            return !claims.getExpiration().before(new Date());
        } catch (JwtException | NullPointerException exception) {
            return false;
        }
    }

    // 토큰에서 subject 추출해서 authentication 리턴
    public Authentication getAuthentication(String jwt) {

        String userName = Jwts.parserBuilder()
                .setSigningKey(stringToKey(secretKey))
                .build()
                .parseClaimsJws(jwt).getBody().getSubject();

        UserContext userContext = (UserContext) userDetailsService.loadUserByUsername(userName);

        return new UsernamePasswordAuthenticationToken(userContext.getAccount().getUserName(), null, userContext.getAuthorities());
    }
}
