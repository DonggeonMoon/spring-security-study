package com.securitystudy.basic.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.ArrayList;
import java.util.List;

@RestController
public class WelcomeController {
    @GetMapping("/welcome")
    public String sayWelcome() {
        return "Welcome to Spring Application with Security";
    }

    public static void main(String[] args) {
        List<String> stringList = new ArrayList<>();
        stringList.add("ddfa");

        stringList.clear();
    }
}
