package com.example.application;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class TokenService {

    private static final Logger LOGGER = LoggerFactory.getLogger(TokenService.class);

    public String getToken(TokenRequest request) {
        LOGGER.info("Generating token for client {} in environment {}", request.clientId(), request.environment());
        return "stubbed-jwt-token";
    }
}
