package io.springsecurity.jwt.repository;

import io.springsecurity.jwt.domain.Account;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class UserRepositoryTest {

    @Autowired
    UserRepository userRepository;

    @Test
    void 회원찾기() {
        Account account = Account.builder()
                .userName("test")
                .password("1111")
                .role("ROLE_USER")
                .build();

        userRepository.save(account);

        Account findAccount = userRepository.findByUserName(account.getUserName())
                .orElseThrow(() -> new IllegalStateException());

        Assertions.assertThat(findAccount.getUserName()).isEqualTo(account.getUserName());
    }

}