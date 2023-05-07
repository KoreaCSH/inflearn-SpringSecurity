package com.core.springsecurity.io.core.security.service.impl;

import com.core.springsecurity.io.core.security.domain.Account;
import com.core.springsecurity.io.core.security.domain.AccountDto;
import com.core.springsecurity.io.core.security.repository.UserRepository;
import com.core.springsecurity.io.core.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service("userService")
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    @Transactional
    public void createUser(AccountDto accountDto) {

        validateDuplicateAccount(accountDto.getUsername());

        Account account = accountDto.toEntity();
        userRepository.save(account);

    }

    private void validateDuplicateAccount(String username) {
        userRepository.findByUsername(username).ifPresent(
                a -> {throw new IllegalStateException("Can't join");}
        );
    }

    @Override
    public Account findById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> new IllegalStateException("멤버가 없습니다."));
    }

}
