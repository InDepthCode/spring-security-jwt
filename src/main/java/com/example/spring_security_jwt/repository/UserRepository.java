package com.example.spring_security_jwt.repository;

import com.example.spring_security_jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username); // Amrut123
    boolean existsByUsername(String username);
}
