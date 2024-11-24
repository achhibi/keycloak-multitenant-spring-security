package org.sfeir.lab.keycloak.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties(prefix = "jwt.auth.realm")
public record IssuersProperties(List<String> issuers) {
}