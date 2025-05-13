package com.bankapp.model;

import lombok.Data;
import java.util.UUID;

@Data
public class Account {
    private String id;
    private String accountNumber;
    private String cardNumber;
    private double balance;

    public Account() {
        this.id = UUID.randomUUID().toString();
        this.accountNumber = UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        this.cardNumber = UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    public String getId() {
        return id;
    }

    public String getAccountNumber() {
        return accountNumber;
    }

    public String getCardNumber() {
        return cardNumber;
    }

    public double getBalance() {
        return balance;
    }

    public void setBalance(double balance) {
        this.balance = balance;
    }
}
