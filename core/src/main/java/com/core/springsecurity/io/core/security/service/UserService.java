package com.core.springsecurity.io.core.security.service;

import com.core.springsecurity.io.core.security.domain.Account;
import com.core.springsecurity.io.core.security.domain.AccountDto;

import java.util.Optional;

public interface UserService {

    void createUser(AccountDto accountDto);

    Account findById(Long id);


}
