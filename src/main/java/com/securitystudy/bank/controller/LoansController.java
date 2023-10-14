package com.securitystudy.bank.controller;

import com.securitystudy.bank.model.Customer;
import com.securitystudy.bank.model.Loans;
import com.securitystudy.bank.repository.CustomerRepository;
import com.securitystudy.bank.repository.LoanRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class LoansController {
    private final LoanRepository loanRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myLoans")
    //@PostAuthorize("hasRole('USER')")
    public List<Loans> getLoanDetails(@RequestParam String email) {
        List<Customer> customers = customerRepository.findByEmail(email);
        if (customers != null && !customers.isEmpty()) {
            return loanRepository.findByCustomerIdOrderByStartDtDesc(customers.get(0).getId());
        }
        return null;
    }
}
