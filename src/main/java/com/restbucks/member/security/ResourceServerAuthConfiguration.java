package com.restbucks.member.security;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

@Configuration
@EnableResourceServer
//The @EnableResourceServer annotation creates a security filter with @Order(3) by default, so by moving the main application security to @Order(6) we ensure that the rule for "/me" takes precedence.
public class ResourceServerAuthConfiguration extends ResourceServerConfigurerAdapter {
    @Override
    public void configure(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .antMatcher("/me")
            .authorizeRequests().anyRequest().authenticated();
        // @formatter:on
    }
}
