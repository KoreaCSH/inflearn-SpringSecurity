package io.springsecurity.jwt.domain.dto;

import io.springsecurity.jwt.domain.Account;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class UserJoinRequest {

    private String userName;
    private String password;
    private String role;

    public Account toEntity(String password) {
        return Account.builder()
                .userName(userName)
                .password(password)
                .role(role)
                .build();
    }
}
