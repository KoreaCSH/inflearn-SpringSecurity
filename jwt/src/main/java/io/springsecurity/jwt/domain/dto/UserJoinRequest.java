package io.springsecurity.jwt.domain.dto;

import io.springsecurity.jwt.domain.User;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;

@AllArgsConstructor
@NoArgsConstructor
@Getter
public class UserJoinRequest {

    private String userName;
    private String password;

    public User toEntity(String password) {
        return User.builder()
                .userName(userName)
                .password(password)
                .build();
    }

}
