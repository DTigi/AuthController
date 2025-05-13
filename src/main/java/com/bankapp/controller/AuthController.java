package com.bankapp.controller;

import com.bankapp.model.Client;
import com.bankapp.service.ClientService;
import com.bankapp.util.SessionManager;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;


@RestController
@RequestMapping("/auth")
public class AuthController {
    private final ClientService clientService;
    private final SessionManager sessionManager;

    public AuthController(ClientService clientService, SessionManager sessionManager) {
        this.clientService = clientService;
        this.sessionManager = sessionManager;
    }

    @Operation(summary = "Регистрация в системе",
            description = "Регистрирует указанного пользователя в системе",
            requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Данные для регистрации",
                    content = @Content(
                            mediaType = "application/json")
            ))
    @PostMapping("/register")
    public Client register(@RequestParam String fullName, @RequestParam String phone,
                           @RequestParam String username, @RequestParam String password) {
        return clientService.register(fullName, phone, username, password);
    }

    @Operation(summary = "Установка таймаута перед ответом",
            description = "Устанавливает таймаут перед ответом на запрос пользователя")
    @PostMapping("/setTimeout")
    public ResponseEntity<String> setTimeout(@RequestParam Integer timeout) {
        //    tmp=timeout;
        return ResponseEntity.ok("");
    }

    @Operation(summary = "Вход в систему",
            description = "Выполняет вход пользователя в систему")
    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        try {
            Thread.sleep(10);
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
        Optional<Client> clientOpt = clientService.login(username, password);
        if (clientOpt.isPresent()) {
            sessionManager.login(clientOpt.get());
            return "✅ Успешный вход: " + username;
        }
        return "❌ Ошибка: Неверный логин или пароль";
    }

    @Operation(summary = "Выход из системы",
            description = "Выполняет выход пользователя из системы")
    @PostMapping("/logout")
    public String logout() {
        sessionManager.logout();
        return "✅ Успешный выход";
    }

    @Operation(summary = "Статус авторизации",
            description = "Возвращает объект пользователя если выполнен вход в систему. " +
                    "В противном случае возвращает строку \"не аутентифицирован\"")
    @GetMapping("/current")
    public ResponseEntity<?> getCurrentClient() {
        Client client = sessionManager.getLoggedInClient();
        if (client == null) {
            return ResponseEntity.status(401).body("не аутентифицирован");
        }
//        System.out.println(client);
        return ResponseEntity.ok(client);
    }

}