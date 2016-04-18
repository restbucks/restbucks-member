package com.restbucks.member.api;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
public class UserResource {

    @RequestMapping({"/user", "/me"})
    protected Map<String, String> user(Principal principal) {
        return new LinkedHashMap<String, String>() {
            {
                put("name", principal.getName());
            }
        };
    }


}
