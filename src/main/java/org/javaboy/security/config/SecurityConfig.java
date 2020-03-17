package org.javaboy.security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

/**
 * Spring Security配置
 */
@Configuration  //注释掉演示多个httpSecurity的配置
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)  //开启方法安全
public class SecurityConfig extends WebSecurityConfigurerAdapter {

//    /**
//     * 告知系统现在密码不用加密
//     */
//    @Bean
//    PasswordEncoder passwordEncoder(){
//        return NoOpPasswordEncoder.getInstance();
//    }

    /**
     * BC加密算法
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置用户名和密码---->从security5之后用户密码必须加密
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("javaboy").password("$2a$10$MNr4geFktw/Vq49JyBm9QO7GH2hQ0i0i7yPtCfdB0vpSK3ykD4Krm").roles("admin")
            .and()
            .withUser("ddg").password("$2a$10$SFKbDfUgIYKiFvueJTBdq.Q5yOCn4M0Nz0apohzSEyWzQm4dVEH/.").roles("user");
    }

    /**
     * HttpSecurity配置多种不同的拦截策略
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //开启安全配置
        http.authorizeRequests()
                .antMatchers("/admin/**").hasAnyRole("admin")
//                .antMatchers("/user/**").hasAnyRole("admin", "user")
                //授权的第二种写法
                .antMatchers("/user/**").access("hasRole('user')")
                //其他的url登录之后即可访问
                .anyRequest().authenticated()
                .and()
                .formLogin()
                //登录页面请求地址---->前后端分离的项目不会配置这个东西所谓的登录接口其实就是返回一个JSON数据
                .loginPage("/login")
                //处理登录的接口
                .loginProcessingUrl("/doLogin")
                //表单用户名
                .usernameParameter("username")
                //表单密码
                .passwordParameter("password")
                //前后端分离项目使用这个方法告诉前端登录成功的信息
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //authentication保存了登录成功的用户的信息
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter out = response.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        //用户身份牌对象
                        map.put("msg", authentication.getPrincipal());
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //登录成功之后跳转到某个页面
//                .successForwardUrl("")
                //前后端分离项目使用这个方法告诉前端登录失败的信息
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException, ServletException {
                        //e异常信息
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter out = response.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 401);
                        if (e instanceof LockedException){
                            map.put("msg","账户被锁定,登录失败");
                        }else if (e instanceof BadCredentialsException){
                            map.put("msg","用户名或密码输入错误,登陆失败");
                        }else if (e instanceof DisabledException){
                            map.put("msg","账户被禁用,登陆失败");
                        }else if (e instanceof AccountExpiredException){
                            map.put("msg","账户过期,登陆失败");
                        }else if (e instanceof CredentialsExpiredException){
                            map.put("msg","密码过期,登陆失败");
                        }else{
                            map.put("msg", "登录失败");
                        }
                        //用户身份牌对象
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //登录失败之后跳转到某个页面
//                .failureForwardUrl("")
                //处理登录请求的地址直接允许通过
                .permitAll()
                .and()
                //登录注销
                .logout()
                //登录注销的请求地址
                .logoutUrl("/logout")
                //前后端分离项目中使用
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        //authentication登录用户的信息
                        response.setContentType("application/json;charset=utf-8");
                        PrintWriter out = response.getWriter();
                        Map<String, Object> map = new HashMap<>();
                        map.put("status", 200);
                        //用户身份牌对象
                        map.put("msg", "注销登录成功");
                        out.write(new ObjectMapper().writeValueAsString(map));
                        out.flush();
                        out.close();
                    }
                })
                //注销成功后做页面跳转
//                .logoutSuccessUrl("")
                .and()
                //使用postman测试关闭csrf攻击
                .csrf().disable();
    }
}
