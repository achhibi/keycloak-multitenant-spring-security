package org.sfeir.lab.keycloak.service;

import org.springframework.security.access.prepost.PostFilter;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;


@Service
public class HelloService {

    @PostFilter("filterObject == authentication.name")
    public List<String> getAuthenticatedName(){
        return new ArrayList<>(List.of("user1", "user2", "user3"));
    }
}
