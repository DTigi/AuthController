package com.bankapp.repository;

import com.bankapp.model.Account;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Repository
public class AccountRepository {
    private final Map<String, Account> accounts = new HashMap<>();

    public Account save(Account account) {
        accounts.put(account.getId(), account);
        return account;
    }

    public Optional<Account> findByNumber(String number) {
        return accounts.values()
                .stream()
                .filter(a -> a.getAccountNumber().equals(number))
                .findFirst();
    }
}
