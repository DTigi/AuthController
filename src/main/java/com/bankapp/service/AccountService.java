package com.bankapp.service;

import com.bankapp.repository.AccountRepository;
import com.bankapp.model.Account;
import com.bankapp.model.Client;
import com.bankapp.repository.ClientRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AccountService {
    private  final AccountRepository accountRepository;

    public Account createAccount(String clientId) {
        Optional<Client> clientOpt = ClientRepository.findById(clientId);
        if (clientOpt.isEmpty()) {
            throw new RuntimeException("Client not found");
        }

        Account account = new Account();
        clientOpt.get().getAccounts().add(account);
        return accountRepository.save(account);
    }

    public Optional<Account> findByNumber(String number) {
        return accountRepository.findByNumber(number);
    }
}
