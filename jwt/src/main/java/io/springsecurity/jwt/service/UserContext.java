package io.springsecurity.jwt.service;

import io.springsecurity.jwt.domain.Account;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

@Getter
public class UserContext extends User {

    private Account account;

    public UserContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUserName(), account.getPassword(), authorities);
        this.account = account;
    }

}
