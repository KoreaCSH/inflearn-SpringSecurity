package com.core.springsecurity.io.core.security.security.handler.form;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class CustomAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        String errorMessage = "Invalid Username or Password";

        // 예외 타입에 따라 message 던지기
        if(exception instanceof BadCredentialsException) {
            errorMessage = "Invalid Username or Password";
        } else if(exception instanceof InsufficientAuthenticationException) {
            // FormWebAuthenticationDetails 에서 설정했던 예외
            errorMessage = "Invalid Secret Key";
        }

        setDefaultFailureUrl("/login?error=true&exception=" + errorMessage);
        super.onAuthenticationFailure(request, response, exception);
    }

}
