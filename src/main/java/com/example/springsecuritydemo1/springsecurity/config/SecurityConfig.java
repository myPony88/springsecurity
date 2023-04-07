package com.example.springsecuritydemo1.springsecurity.config;

import com.example.springsecuritydemo1.springsecurity.handler.AuthenticationEntryPointIHandler;
import com.example.springsecuritydemo1.springsecurity.service.BaseUserDetailsService;
import com.example.springsecuritydemo1.springsecurity.service.impl.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import javax.annotation.Resource;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/20 14:30
 */
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    @Autowired
    SpringSecurityAdminConfig springSecurityAdminConfig;

    @Autowired
    SpringSecurityMobileConfig springSecurityMobileConfig;

    @Autowired
    UserDetailServiceImpl userDetailService;

    @Autowired
    AuthenticationEntryPointIHandler authenticationEntryPointIHandler;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(AbstractHttpConfigurer::disable)
                .sessionManagement(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auhtor-> auhtor
                        .antMatchers("/admin/code", "/admin/login","/mobile/code","/mobile/login").permitAll()
                        .anyRequest().authenticated())
                .cors();
        //后台登录配置
        http.apply(springSecurityAdminConfig);
        //注入新的AuthenticationManager
        http.authenticationManager(authenticationManager(http));

        //手机登录配置
        http.apply(springSecurityMobileConfig);

        http.exceptionHandling(ex->ex.authenticationEntryPoint(authenticationEntryPointIHandler));

        return http.build();
    }

    /**
     *密码加密规则
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    /**
     *构造一个AuthenticationManager，使用自定义的userDetailsService和passwordEncoder
     */
    @Bean
    AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManagerBuilder.class)
                .userDetailsService(userDetailService)
                .passwordEncoder(passwordEncoder())
                .and()
                .build();
        return authenticationManager;
    }

}
