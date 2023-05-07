package com.core.springsecurity.io.core.security.repository;

import com.core.springsecurity.io.core.security.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByUsername(String username);


}
