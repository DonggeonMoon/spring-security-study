package com.securitystudy.bank.controller;

import com.securitystudy.bank.model.Cards;
import com.securitystudy.bank.model.Customer;
import com.securitystudy.bank.repository.CardsRepository;
import com.securitystudy.bank.repository.CustomerRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequiredArgsConstructor
public class CardsController {
    private final CardsRepository cardsRepository;
    private final CustomerRepository customerRepository;

    @GetMapping("/myCards")
    public List<Cards> getCardDetails(@RequestParam String email) {
        List<Customer> customers = customerRepository.findByEmail(email);
        if (customers != null && !customers.isEmpty()) {
            return cardsRepository.findByCustomerId(customers.get(0).getId());
        }
        return null;
    }
}
