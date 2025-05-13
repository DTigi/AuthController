package com.bankapp.model;

import lombok.Data;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Data
public class Client {
    private String id;
    private String fullName;
    private String phone;
    private String username;
    private String password;
    private List<Account> accounts = new ArrayList<>();

    public Client(String fullName, String phone, String username, String password) {
        this.id = UUID.randomUUID().toString();
        this.fullName = fullName;
        this.phone = phone;
        this.username = username;
        this.password = password;
    }

    public String getFullName() {
        return fullName;
    }

    public String getId() {
        return id;
    }

    public String getPhone() {
        return phone;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public List<Account> getAccounts() {
        return accounts;
    }

}
