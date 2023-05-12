package io.springsecurity.jwt.configuration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class EncoderConfig {

    public BCryptPasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

}
