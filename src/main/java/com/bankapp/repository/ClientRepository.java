package com.bankapp.repository;

import com.bankapp.model.Client;
import java.util.*;

public class ClientRepository {
    private static final Map<String, Client> clients = new HashMap<>();

    public static Client save(Client client) {
        clients.put(client.getId(), client);
        return client;
    }

    public static Optional<Client> findByUsername(String username) {
        return clients.values().stream()
                .filter(c -> c.getUsername().equals(username))
                .findFirst();
    }

    public static Optional<Client> findById(String id) {
        return Optional.ofNullable(clients.get(id));
    }

    public static Collection<Client> getAllClients() {
        return clients.values();
    }
}