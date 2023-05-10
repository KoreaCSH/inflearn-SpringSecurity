package com.core.springsecurity.io.core.security.security.provider.ajax;

import com.core.springsecurity.io.core.security.security.common.FormWebAuthenticationDetails;
import com.core.springsecurity.io.core.security.security.service.AccountContext;
import com.core.springsecurity.io.core.security.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.transaction.Transactional;

@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {

    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        String username = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext) userDetailsService.loadUserByUsername(username);

        // AccountContext 는 User 를 상속받는다. accountContext.getPassword() 는 User 의 필드를 사용하는 것이므로
        // accountContext.getAccount().getPassword() 을 해야 한다.
        if (!passwordEncoder.matches(password, accountContext.getAccount().getPassword())) {
            throw new BadCredentialsException("BadCredentialsException");
        }

        // token 을 만들어서 AuthenticationProvider 를 호출한 AuthenticationManager 에게 return 한다.
        return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AjaxAuthenticationToken.class.isAssignableFrom(authentication);
    }

}
