package com.securitystudy.bank.controller;

import com.securitystudy.bank.model.AccountTransactions;
import com.securitystudy.bank.model.Customer;
import com.securitystudy.bank.repository.AccountTransactionsRepository;
import com.securitystudy.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class BalanceController {
    private final AccountTransactionsRepository accountTransactionsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myBalance")
    public List<AccountTransactions> getBalanceDetails(@RequestParam String email) {
        List<Customer> customers = customerRepository.findByEmail(email);
        if (customers != null && !customers.isEmpty()) {
            return accountTransactionsRepository.findByCustomerIdOrderByTransactionDtDesc(customers.get(0).getId());
        }
        return null;
    }
}
