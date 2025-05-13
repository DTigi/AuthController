package com.bankapp.standartmock;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = "com.bankapp")
public class MyMock {
    public static void main(String[] args) {
        SpringApplication.run(MyMock.class, args);
    }
}
//Spring Boot
//Spring Framework
//ApplicationServer - Tomcat
//        Map<String,Object>