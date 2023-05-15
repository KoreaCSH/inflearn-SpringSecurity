package io.springsecurity.jwt.controller;

import io.springsecurity.jwt.domain.Account;
import io.springsecurity.jwt.service.AuthUser;
import io.springsecurity.jwt.service.UserContext;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/reviews")
public class ReviewController {

    @PostMapping
    public ResponseEntity<String> writeReview(@AuthUser Account account) {
        String userName = account.getUserName();
        return ResponseEntity.ok().body(userName + "님의 리뷰 동작이 완료 되었습니다");
    }

}
