package com.securitystudy.bank.controller;

import com.securitystudy.bank.model.AccountTransactions;
import com.securitystudy.bank.repository.AccountTransactionsRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class BalanceController {
    private final AccountTransactionsRepository accountTransactionsRepository;

    @GetMapping("/myBalance")
    public List<AccountTransactions> getBalanceDetails(@RequestParam int id) {
        return accountTransactionsRepository.
                findByCustomerIdOrderByTransactionDtDesc(id);
    }
}
