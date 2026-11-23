package io.github.romontero.security.auth.domain.model;

public record TokenRequest (
        String username,
        String password
){}
