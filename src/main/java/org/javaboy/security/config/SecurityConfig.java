package org.javaboy.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Spring Security配置
 */
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    /**
     * 告知系统现在密码不用加密
     */
    @Bean
    PasswordEncoder passwordEncoder(){
        return NoOpPasswordEncoder.getInstance();
    }

    /**
     * 配置用户名和密码---->从security5之后用户密码必须加密
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
            .withUser("javaboy").password("1").roles("admin")
            .and()
            .withUser("ddg").password("1").roles("user");
    }

    /**
     * HttpSecurity配置多种不同的拦截策略
     * @param http
     * @throws Exception
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
                //处理登录请求的地址直接允许通过
                .loginProcessingUrl("/doLogin")
                .permitAll()
                .and()
                //使用postman测试关闭csrf攻击
                .csrf().disable();
    }
}
