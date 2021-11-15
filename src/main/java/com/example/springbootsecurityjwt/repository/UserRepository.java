package com.example.springbootsecurityjwt.repository;

import com.example.springbootsecurityjwt.entity.User;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {

    @EntityGraph(attributePaths = "authorities") // authorities 를 지연이 아닌 바로 가져옴..
    Optional<User> findOneWithAuthoritiesByUsername(String username);

}
