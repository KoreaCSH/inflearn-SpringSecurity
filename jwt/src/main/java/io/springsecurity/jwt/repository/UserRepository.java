package io.springsecurity.jwt.repository;

import io.springsecurity.jwt.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByUserName(String userName);

}
