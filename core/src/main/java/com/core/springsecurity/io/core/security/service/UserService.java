package com.core.springsecurity.io.core.security.service;

import com.core.springsecurity.io.core.security.domain.Account;
import com.core.springsecurity.io.core.security.domain.AccountDto;

public interface UserService {

    void createUser(AccountDto accountDto);


}
