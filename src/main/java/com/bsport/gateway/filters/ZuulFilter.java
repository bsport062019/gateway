package com.bsport.gateway.filters;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Created by IntelliJ IDEA.
 * User: Truong Nguyen
 * Date: 17-Dec-18
 * Time: 10:20 AM
 * To change this template use File | Settings | File Templates.
 */
@Configuration
public class ZuulFilter {
    @Bean
    public AuthenticationPreFilter authenticationPreFilter() {
        return new AuthenticationPreFilter();
    }
}
