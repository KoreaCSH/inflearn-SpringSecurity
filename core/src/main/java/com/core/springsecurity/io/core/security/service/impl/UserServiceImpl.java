package com.core.springsecurity.io.core.security.service.impl;

import com.core.springsecurity.io.core.security.domain.Account;
import com.core.springsecurity.io.core.security.domain.AccountDto;
import com.core.springsecurity.io.core.security.repository.UserRepository;
import com.core.springsecurity.io.core.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service("userService")
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;

    @Override
    public void createUser(AccountDto accountDto) {

        Account account = accountDto.toEntity();
        userRepository.save(account);
    }
}
