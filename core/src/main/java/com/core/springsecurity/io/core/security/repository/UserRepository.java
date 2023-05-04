package com.core.springsecurity.io.core.security.repository;

import com.core.springsecurity.io.core.security.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, Long> {

}
