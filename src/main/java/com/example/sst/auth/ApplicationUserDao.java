package com.example.sst.auth;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

public interface ApplicationUserDao {
    Optional<UserDetails> selectApplicationUserByUsername(String username);
}
