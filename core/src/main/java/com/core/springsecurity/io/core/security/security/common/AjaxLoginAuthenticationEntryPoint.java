package com.core.springsecurity.io.core.security.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// EntryPoint, AccessDeniedHandler 의 정확한 차이는?
// 인증을 받지 않은 사용자가 자원에 접근할 때에는 EntryPoint
// 인증은 받았지만 role 을 충족하지 못한다면 AccessDeniedHandler
public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {

        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");

    }
}
