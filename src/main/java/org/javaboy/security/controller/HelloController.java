package org.javaboy.security.controller;

import org.javaboy.security.service.MethodService;
import org.springframework.beans.factory.annotation.Autowired;
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

    @GetMapping("/login")
    public String login(){
        return "Please Login";
    }

    //-----------------以下三个接口登录后都可以访问但是不一定能调用里面的方法

    @Autowired
    MethodService methodService;

    @GetMapping("/hello1")
    public String helloAdmin(){
        return methodService.admin();
    }

    @GetMapping("/hello2")
    public String helloUser(){
        return methodService.user();
    }

    @GetMapping("/hello3")
    public String helloHello(){
        return methodService.hello();
    }

}
