package com.restbucks.member.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.UUID;

import static java.lang.String.format;

@Slf4j
@Component
public class LocalUserRegistrar {

    @Autowired
    private UserDetailsManager userDetailsManager;

    @EventListener
    protected void createOrUpdateLocalUserGiven(InteractiveAuthenticationSuccessEvent event) {
        String userName = event.getAuthentication().getName();
        if (userDetailsManager.userExists(userName)) {
            //TODO: update user's profile?
            log.info(format("skip local user creation since [%s] exists", userName));
        } else {
            log.info(format("begin local user creation for [%s]", userName));
            User user = new User(userName,
                    UUID.randomUUID().toString(), // The user should login with the external provider
                    new ArrayList<GrantedAuthority>() {
                        {
                            add(new SimpleGrantedAuthority("ROLE_USER"));
                        }
                    });
            userDetailsManager.createUser(user);
            log.info(format("End local user creation for [%s]", userName));
        }
    }
}
