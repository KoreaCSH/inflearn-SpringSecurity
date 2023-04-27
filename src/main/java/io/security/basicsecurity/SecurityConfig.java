package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // web 보안 활성화 애노테이션
@RequiredArgsConstructor
public class SecurityConfig {

    // SpringBoot 2.7.x 는 SpringSecurity 5.7.x 버전이 추가되는데,
    // SpringSecurity 5.7.x 버전부터 WebSecurityConfigurerAdapter 가 deprecated 되어
    // 이제 WebSecurityConfigurerAdapter 를 상속받는 것이 아니라
    // SecurityFilterChain 을 Bean 으로 등록해야 한다.

    private final UserDetailsService userDetailsService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 인가
        http
                .authorizeRequests()
                .anyRequest().authenticated();

        // 인증 - 로그인
        http
                .formLogin() // Form 로그인 인증 기능 작동
                //.loginPage("/loginPage") // 사용자 정의 로그인 페이지
                .defaultSuccessUrl("/") // 로그인 성공 후 이동 페이지
                .failureUrl("/login") // 로그인 실패 후 이동 페이지
                .usernameParameter("userId") // 아이디 파라미터명 설정
                .passwordParameter("password") // 패스워드 파라미터명 설정
                .loginProcessingUrl("/login_proc") // 로그인 Form Action Url - /login_proc 으로 post 요청 보내는 것
                .successHandler(new AuthenticationSuccessHandler() { // 로그인 성공 후 handler
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication " + authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() { // 로그인 실패 후 handler
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception " + exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll(); // 모든 요청에 대해 인증 필요한 상황이라 /loginPage 로 이동하는 데에도 로그인 필요. 이를 방지하기 위해 /loginPage 에는 permitAll()

        // 인증 - 로그아웃
        http
                .logout() // 로그아웃 처리
                .logoutUrl("/logout") // 로그아웃 처리 url - 원칙적으로 Post 방식으로만 처리할 수 있다.
                .logoutSuccessUrl("/login") // 로그아웃 성공 후 이동페이지
                .addLogoutHandler(new LogoutHandler() {  // 로그아웃 핸들러 - 기본적으로 SpringSecurity 의 logoutHandler 가 구현되어 있다.
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession(false);
                        if(session != null) {
                            session.invalidate();
                        }
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() { // 로그아웃 성공 후 핸들러 - 로그인 페이지로 redirect
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember") // 로그아웃 후 쿠키 삭제
                // remember-me 구현
                .and()
                .rememberMe() // remember-me 기능 활성화
                .rememberMeParameter("remember") // 기본 파라미터명은 remember-me
                .tokenValiditySeconds(3600) // default 는 14일
                .alwaysRemember(false) // remember-me 기능이 활성화되지 않아도 항상 실행할 것인가
                .userDetailsService(userDetailsService); // 기능을 사용할 때 사용자 정보가 필요하므로 반드시 해당 설정이 필요하다.

        // 동시 세션 제어 - (1) 이전 사용자 세션 만료 / (2) 현재 사용자 인증 실패
        //http
        //        .sessionManagement(session -> session
        //                    .maximumSessions(1) // 최대 허용 가능 세션 수, -1 이라면 무제한 세션 허용
        //                    .maxSessionsPreventsLogin(true) // true - 현재 사용자 인증 실패 / false - 이전 사용자 세션 만료
        //                    .expiredUrl("/expired") // 세션이 만료된 경우 이동할 페이지
        //            );
        http
                .sessionManagement()
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true);
                //.expiredUrl();

        // 동시 세션 제어와 세션 고정 보호를 따로 설정해야 하는 이유는?
        // 세션 고정 보호 - sessionFixation().changeSessionId() 는 SpringSecurity 가 기본으로 설정해 준다.
        // 공격자가 제공하는 JsessionID 를 사용하여 사용자가 로그인하는 것을 방지하기 위해
        // changeSessionId 를 통해 JsessionID 를 변경하도록 설정한다.
        http
                .sessionManagement()
                .sessionFixation().changeSessionId();
                //.invalidSessionUrl();

        return http.build();
    }

//    @Bean
//    public HttpSessionEventPublisher httpSessionEventPublisher() {
//        return new HttpSessionEventPublisher();
//    }


}
