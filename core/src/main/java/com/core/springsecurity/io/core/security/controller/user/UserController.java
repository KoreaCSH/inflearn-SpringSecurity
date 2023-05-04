package com.core.springsecurity.io.core.security.controller.user;

import com.core.springsecurity.io.core.security.domain.AccountDto;
import com.core.springsecurity.io.core.security.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }

    @GetMapping("/users")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("users")
    public String createUser(AccountDto accountDto) {

        accountDto.setPassword(passwordEncoder.encode(accountDto.getPassword()));

        userService.createUser(accountDto);

        return "redirect:/";
    }

}
