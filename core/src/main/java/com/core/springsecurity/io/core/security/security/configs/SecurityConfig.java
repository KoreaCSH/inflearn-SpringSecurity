//package com.core.springsecurity.io.core.security.security.configs;
//
//import com.core.springsecurity.io.core.security.security.filter.AjaxLoginProcessingFilter;
//import com.core.springsecurity.io.core.security.security.handler.form.CustomAccessDeniedHandler;
//import com.core.springsecurity.io.core.security.security.handler.form.CustomAuthenticationFailureHandler;
//import com.core.springsecurity.io.core.security.security.handler.form.CustomAuthenticationSuccessHandler;
//import com.core.springsecurity.io.core.security.security.provider.form.CustomAuthenticationProvider;
//import lombok.RequiredArgsConstructor;
//import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.security.authentication.AuthenticationDetailsSource;
//import org.springframework.security.authentication.AuthenticationManager;
//import org.springframework.security.authentication.AuthenticationProvider;
//import org.springframework.security.authentication.ProviderManager;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.crypto.factory.PasswordEncoderFactories;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.provisioning.InMemoryUserDetailsManager;
//import org.springframework.security.web.SecurityFilterChain;
//import org.springframework.security.web.access.AccessDeniedHandler;
//import org.springframework.security.web.authentication.AuthenticationFailureHandler;
//import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
//import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
//
//@Configuration
//@EnableWebSecurity
//@Order(1)
//@RequiredArgsConstructor
//public class SecurityConfig {
//
//    // 5.7.x 부터는 CustomUserDatailsService 를 Bean 으로 등록만 하면 되는 듯 하다.
//    private final UserDetailsService userDetailsService;
//    private final AuthenticationDetailsSource authenticationDetailsSource;
//
//
//    // AuthenticationManager
//    @Bean
//    public AuthenticationManager authenticationManager() {
//        return new ProviderManager(authenticationProvider());
//    }
//
//    // CustomAuthenticationProvider
//    @Bean
//    public AuthenticationProvider authenticationProvider() {
//        return new CustomAuthenticationProvider(userDetailsService, passwordEncoder());
//    }
//
//    @Bean
//    public AccessDeniedHandler accessDeniedHandler() {
//        CustomAccessDeniedHandler accessDeniedHandler = new CustomAccessDeniedHandler();
//        accessDeniedHandler.setErrorPage("/denied");
//
//        return accessDeniedHandler;
//    }
//
////    @Bean
////    public UserDetailsService userDetailsService() {
////
////        String password = passwordEncoder().encode("1111");
////
////        UserDetails user = User.builder()
////                .username("user")
////                .password(password)
////                .roles("USER")
////                .build();
////
////        UserDetails admin = User.builder()
////                .username("admin")
////                .password(password)
////                .roles("ADMIN")
////                .build();
////
////        UserDetails sys = User.builder()
////                .username("manager")
////                .password(password)
////                .roles("MANAGER")
////                .build();
////
////        return new InMemoryUserDetailsManager(user, admin, sys);
////    }
//
//    @Bean
//    public PasswordEncoder passwordEncoder() {
//        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
//    }
//
//    // WebIgnore - css, image 파일 등은 필터를 거치지 않게 설정
//    @Bean
//    public WebSecurityCustomizer webSecurityCustomizer() {
//        return (web -> web.ignoring().requestMatchers(PathRequest.toStaticResources().atCommonLocations()));
//    }
//
//    @Bean
//    public AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return new CustomAuthenticationSuccessHandler();
//    }
//
//    @Bean
//    public AuthenticationFailureHandler authenticationFailureHandler() {
//        return new CustomAuthenticationFailureHandler();
//    }
//
//    @Bean
//    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//
//        http
//                .authorizeRequests(authorize -> authorize
//                        .mvcMatchers("/", "/users", "user/login/login/**", "/login*").permitAll()
//                        .mvcMatchers("/mypage").hasRole("USER")
//                        .mvcMatchers("/messages").hasRole("MANAGER")
//                        .mvcMatchers("/config").hasRole("ADMIN")
//                        .anyRequest().authenticated());
//
//        http
//                .formLogin()
//                .loginPage("/login")
//                .loginProcessingUrl("/login_proc")
//                .authenticationDetailsSource(authenticationDetailsSource)
//                .defaultSuccessUrl("/")
//                .successHandler(authenticationSuccessHandler())
//                .failureHandler(authenticationFailureHandler())
//                .permitAll();
//
//        http
//                .exceptionHandling()
//                .accessDeniedHandler(accessDeniedHandler());
//
//        return http.build();
//    }
//
//}
