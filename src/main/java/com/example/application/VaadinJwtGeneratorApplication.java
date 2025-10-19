package com.example.application;

import com.vaadin.flow.spring.desktop.EnableVaadinDesktop;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.builder.SpringApplicationBuilder;

@SpringBootApplication
@EnableVaadinDesktop
public class VaadinJwtGeneratorApplication {

    public static void main(String[] args) {
        new SpringApplicationBuilder(VaadinJwtGeneratorApplication.class)
                .headless(false)
                .run(args);
    }
}
