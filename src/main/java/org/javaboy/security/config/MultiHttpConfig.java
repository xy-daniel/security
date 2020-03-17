//package org.javaboy.security.config;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.core.annotation.Order;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.password.NoOpPasswordEncoder;
//import org.springframework.security.crypto.password.PasswordEncoder;
//
///**
// * 多个HttpSecurity的配置类
// */
////@Configuration
//public class MultiHttpConfig {
//
//    @Bean
//    PasswordEncoder passwordEncoder(){
//        return NoOpPasswordEncoder.getInstance();
//    }
//
//    /**
//     * 配置用户名和密码---->从security5之后用户密码必须加密
//     */
//    @Autowired
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.inMemoryAuthentication()
//                .withUser("javaboy").password("1").roles("admin")
//                .and()
//                .withUser("ddg").password("1").roles("user");
//    }
//
//    //静态内部类配置多个HttpSecurity
//
//    //管理员相关配置
//    @Configuration
//    @Order(1)
//    public static class AdminSecurityConfig extends WebSecurityConfigurerAdapter{
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.antMatcher("/admin/**").authorizeRequests().anyRequest().hasRole("admin");
//        }
//    }
//
//    //用户相关配置
//    @Configuration
//    @Order(2)
//    public static class UserSecurityConfig extends WebSecurityConfigurerAdapter{
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.authorizeRequests().anyRequest().authenticated()
//                    .and().formLogin().loginProcessingUrl("/doLogin").permitAll()
//                    .and().csrf().disable();
//        }
//    }
//}
