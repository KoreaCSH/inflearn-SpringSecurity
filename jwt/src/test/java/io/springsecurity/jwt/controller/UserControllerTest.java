package io.springsecurity.jwt.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.springsecurity.jwt.configuration.EncoderConfig;
import io.springsecurity.jwt.configuration.SecurityConfig;
import io.springsecurity.jwt.domain.dto.UserJoinRequest;
import io.springsecurity.jwt.domain.dto.UserLoginRequest;
import io.springsecurity.jwt.exception.AppException;
import io.springsecurity.jwt.exception.ErrorCode;
import io.springsecurity.jwt.exception.ExceptionManager;
import io.springsecurity.jwt.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithAnonymousUser;
import org.springframework.test.annotation.Rollback;
import org.springframework.test.web.servlet.MockMvc;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@WebMvcTest
@Import(SecurityConfig.class)
// 스프링시큐리티 5.7.X 부터는 WebSecurityConfigureAdapter 가 deprecated 되고, SecurityFilterChain 을 사용한다.
// 그로 인해 SecurityFilterChain 이 제대로 동작하지 않을 수 있으므로 @Import(SecurityConfig.class) 로 빈이 동작하도록 하자.
class UserControllerTest {

    @Autowired
    MockMvc mockMvc;

    // java Object 를 Json 으로 만들어주는 Mapper
    @Autowired
    ObjectMapper objectMapper;

    @MockBean
    UserService userService;

    @Test
    @DisplayName("회원가입 성공")
    void join() throws Exception {

        String userName = "test";
        String password = "1111";

        mockMvc.perform(post("/api/v1/users/join")
                        // spring security 설정을 했다면 반드시 csrf() 를 보내야 하며,
                        // 이는 spring-security-test 를 추가해야 한다.
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        // http 에 값을 보낼 땐 Byte 로 보낸다.
                        .content(objectMapper.writeValueAsBytes(new UserJoinRequest(userName, password))))
                .andDo(print())
                .andExpect(status().isOk());

    }

    @Test
    @DisplayName("회원가입 실패 - userName 중복")
    void join_fail() throws Exception {

        String userName = "test";
        String password = "1111";

        when(userService.join(any()))
                .thenThrow(new AppException(ErrorCode.USERNAME_DUPLICATED, "해당 userId가 중복됩니다."));

        mockMvc.perform(post("/api/v1/users/join")
                        .contentType(MediaType.APPLICATION_JSON)
                        // http 에 값을 보낼 땐 Byte 로 보낸다.
                        .content(objectMapper.writeValueAsBytes(new UserJoinRequest(userName, password))))
                .andDo(print())
                .andExpect(status().isConflict());

    }

    @Test
    @WithAnonymousUser
    @DisplayName("로그인 성공")
    void login_success() throws Exception {

        String userName = "test";
        String password = "1111";

        when(userService.login(any()))
                .thenReturn("token");

        mockMvc.perform(post("/api/v1/users/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        // http 에 값을 보낼 땐 Byte 로 보낸다.
                        .content(objectMapper.writeValueAsBytes(new UserLoginRequest(userName, password))))
                .andDo(print())
                .andExpect(status().isOk());

    }

    @Test
    @WithAnonymousUser
    @DisplayName("로그인 실패 - userName 없음")
    void login_failure_userName() throws Exception {

        String userName = "test";
        String password = "1111";

        when(userService.login(any()))
                .thenThrow(new AppException(ErrorCode.USERNAME_NOTFOUND, ""));

        mockMvc.perform(post("/api/v1/users/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        // http 에 값을 보낼 땐 Byte 로 보낸다.
                        .content(objectMapper.writeValueAsBytes(new UserJoinRequest(userName, password))))
                .andDo(print())
                .andExpect(status().isNotFound());

    }

    @Test
    @WithAnonymousUser
    @DisplayName("로그인 실패 - password 틀림")
    void login_failure_password() throws Exception {

        String userName = "test";
        String password = "1111";

        when(userService.login(any()))
                .thenThrow(new AppException(ErrorCode.INVALID_PASSWORD, ""));

        mockMvc.perform(post("/api/v1/users/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_JSON)
                        // http 에 값을 보낼 땐 Byte 로 보낸다.
                        .content(objectMapper.writeValueAsBytes(new UserJoinRequest(userName, password))))
                .andDo(print())
                .andExpect(status().isUnauthorized());

    }

}