package com.securitystudy.bank.controller;

import com.securitystudy.bank.model.Accounts;
import com.securitystudy.bank.model.Customer;
import com.securitystudy.bank.repository.AccountsRepository;
import com.securitystudy.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class AccountController {
    private final AccountsRepository accountsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myAccount")
    public Accounts getAccountDetails(@RequestParam String email) {
        List<Customer> customers = customerRepository.findByEmail(email);
        if (customers != null && !customers.isEmpty()) {
            return accountsRepository.findByCustomerId(customers.get(0).getId());
        }
        return null;
    }
}
