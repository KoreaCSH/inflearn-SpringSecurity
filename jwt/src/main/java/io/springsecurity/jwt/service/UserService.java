package io.springsecurity.jwt.service;

import io.springsecurity.jwt.domain.User;
import io.springsecurity.jwt.domain.dto.UserJoinRequest;
import io.springsecurity.jwt.exception.AppException;
import io.springsecurity.jwt.exception.ErrorCode;
import io.springsecurity.jwt.repository.UserRepository;
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

    @Transactional
    public String join(UserJoinRequest request) {

        // userName 중복 확인
        userRepository.findByUserName(request.getUserName()).ifPresent(
                user -> {throw new AppException(ErrorCode.USERNAME_DUPLICATED,
                        user.getUserName() + "은 이미 있습니다.");}
        );

        String password = encoder.encode(request.getPassword());
        User user = request.toEntity(password);
        userRepository.save(user);

        return "success";
    }

}
