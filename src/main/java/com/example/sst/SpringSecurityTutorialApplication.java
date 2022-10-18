package com.example.sst;

import com.example.sst.jwt.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(JwtConfig.class)
public class SpringSecurityTutorialApplication {

    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityTutorialApplication.class, args);
    }

}
