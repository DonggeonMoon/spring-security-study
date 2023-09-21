package com.securitystudy.basic;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.ComponentScan;

@SpringBootApplication
@ComponentScan("com.securitystudy.basic.controller")
public class SpringSecurityStudyApplication {
    public static void main(String[] args) {
        SpringApplication.run(SpringSecurityStudyApplication.class, args);
    }
}
