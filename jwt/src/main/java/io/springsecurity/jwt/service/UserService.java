package io.springsecurity.jwt.service;

import io.springsecurity.jwt.domain.Account;
import io.springsecurity.jwt.domain.dto.UserJoinRequest;
import io.springsecurity.jwt.domain.dto.UserLoginRequest;
import io.springsecurity.jwt.exception.AppException;
import io.springsecurity.jwt.exception.ErrorCode;
import io.springsecurity.jwt.repository.UserRepository;
import io.springsecurity.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;
    //private final JwtProvider jwtTokenUtils;

    @Transactional
    public String join(UserJoinRequest request) {

        // userName 중복 확인
        userRepository.findByUserName(request.getUserName()).ifPresent(
                user -> {throw new AppException(ErrorCode.USERNAME_DUPLICATED,
                        user.getUserName() + "은 이미 있습니다.");}
        );

        String password = encoder.encode(request.getPassword());
        Account user = request.toEntity(password);
        userRepository.save(user);

        return "success";
    }

//    @Transactional
//    public String login(UserLoginRequest request) {
//
//        Account findUser = userRepository.findByUserName(request.getUserName())
//                .orElseThrow(() -> new AppException(ErrorCode.USERNAME_NOTFOUND, request.getUserName() + "가 없습니다"));
//
//        if (!encoder.matches(request.getPassword(), findUser.getPassword())) {
//            throw new AppException(ErrorCode.INVALID_PASSWORD, "패스워드를 잘못 입력 했습니다.");
//        }
//
//        String token = jwtTokenUtils.createToken(null);
//
//        return token;
//    }

}
