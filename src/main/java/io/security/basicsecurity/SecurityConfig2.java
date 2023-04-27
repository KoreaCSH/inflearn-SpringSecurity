package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;

//@Configuration
//@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig2 {

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin();

        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(false);

        return http.build();
    }

}
