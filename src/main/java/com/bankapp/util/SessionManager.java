package com.bankapp.util;

import com.bankapp.model.Client;
import org.springframework.stereotype.Component;

@Component
public class SessionManager {
    private Client loggedInClient;

    public void login(Client client) {
        this.loggedInClient = client;
    }

    public Client getLoggedInClient() {
        return loggedInClient;
    }

    public void logout() {
        this.loggedInClient = null;
    }

    public boolean isLoggedIn() {
        return loggedInClient != null;
    }
}