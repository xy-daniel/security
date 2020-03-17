package org.javaboy.security.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello(){
        return "Hello Security";
    }

    @GetMapping("/admin/hello")
    public String admin(){
        return "Hello Admin";
    }

    @GetMapping("/user/hello")
    public String user(){
        return "Hello User";
    }
}
