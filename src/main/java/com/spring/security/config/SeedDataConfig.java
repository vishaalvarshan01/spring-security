package com.spring.security.config;

import com.spring.security.models.Role;
import com.spring.security.models.User;
import com.spring.security.repositories.UserRepository;
import com.spring.security.services.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
@Slf4j
public class SeedDataConfig implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final UserService userService;

    @Override
    public void run(String ...args) throws Exception{
        if(userRepository.count() == 0){
            User admin = User.builder().firstName("admin").lastName("admin").email("admin@gmail.com")
                    .password(passwordEncoder.encode("admin")).role(Role.ROLE_ADMIN)
                    .build();
            userService.save(admin);
            log.debug("created ADMIN user - {}", admin);
        }
    }
}
