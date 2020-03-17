package org.javaboy.security.service;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
public class MethodService {

    @PreAuthorize("hasRole('admin')")
    public String admin(){
        return "hello service admin";
    }

    @Secured("ROLE_USER")
    public String user(){
        return "hello service user";
    }

    @PreAuthorize("hasAnyRole('admin', 'user')")
    public String hello(){
        return "hello service";
    }

}
