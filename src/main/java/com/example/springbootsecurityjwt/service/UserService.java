package com.example.springbootsecurityjwt.service;

import com.example.springbootsecurityjwt.SecurityUtil;
import com.example.springbootsecurityjwt.dto.UserDto;
import com.example.springbootsecurityjwt.entity.Authority;
import com.example.springbootsecurityjwt.entity.User;
import com.example.springbootsecurityjwt.exception.DuplicateMemberException;
import com.example.springbootsecurityjwt.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // 회원가입 수행
    @Transactional
    public UserDto signup(UserDto userDto) {

        if (userRepository.findOneWithAuthoritiesByUsername(userDto.getUsername()).orElse(null) != null) {
            throw new DuplicateMemberException("이미 가입되어 있는 유저입니다.");
        }

        Authority authority = Authority.builder()
                .authorityName("ROLE_USER")
                .build();

        User user = User.builder()
                .username(userDto.getUsername())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .nickname(userDto.getNickname())
                .authorities(Collections.singleton(authority))
                .activated(true)
                .build();


        return UserDto.from(userRepository.save(user));
    }

    // username을 기준으로 정보를 가져온다.
    @Transactional(readOnly = true)
    public UserDto getUserWithAuthorities(String username) {
        return UserDto.from(userRepository.findOneWithAuthoritiesByUsername(username).orElse(null));
    }

    // 현재 SecurityContext에 저장된 (getCurrentUsername()) username의 user정보와 권한 정보를 가져온다.
    @Transactional(readOnly = true)
    public UserDto getMyUserWithAuthorities() {
        return UserDto.from(SecurityUtil.getCurrentUsername().flatMap(userRepository::findOneWithAuthoritiesByUsername).orElse(null));
    }
}