package com.core.springsecurity.io.core.security.controller.user;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@RequiredArgsConstructor
public class UserController {

    @GetMapping("/mypage")
    public String myPage() {
        return "user/mypage";
    }

}
