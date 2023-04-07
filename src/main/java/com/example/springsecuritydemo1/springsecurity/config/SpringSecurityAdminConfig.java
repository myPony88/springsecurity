package com.example.springsecuritydemo1.springsecurity.config;

import com.example.springsecuritydemo1.springsecurity.filter.AdminAuthenticationTokenFilter;
import com.example.springsecuritydemo1.springsecurity.filter.AdminUsernamePasswordAuthenticationFilter;
import com.example.springsecuritydemo1.springsecurity.handler.AdminAuthenticationFailureHandler;
import com.example.springsecuritydemo1.springsecurity.handler.AdminAuthenticationSuccessHandler;
import com.example.springsecuritydemo1.springsecurity.handler.AuthenticationEntryPointIHandler;
import com.example.springsecuritydemo1.springsecurity.service.BaseUserDetailsService;
import com.example.springsecuritydemo1.springsecurity.service.impl.UserDetailServiceImpl;
import com.example.springsecuritydemo1.springsecurity.token.AdminUsernamePasswordAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.userdetails.DaoAuthenticationConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;

/**
 * @Description: 后台登录过滤器注入配置
 * @Author: mayanhui
 * @Date: 2023/2/14 12:43
 */
@Component
public class SpringSecurityAdminConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    @Autowired
    AdminAuthenticationSuccessHandler adminAuthenticationSuccessHandler;

    @Autowired
    AdminAuthenticationFailureHandler adminAuthenticationFailureHandler;

    @Autowired
    AdminAuthenticationTokenFilter adminAuthenticationTokenFilter;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        AdminUsernamePasswordAuthenticationFilter adminUsernamePasswordAuthenticationFilter = new AdminUsernamePasswordAuthenticationFilter();
        adminUsernamePasswordAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        adminUsernamePasswordAuthenticationFilter.setAuthenticationSuccessHandler(adminAuthenticationSuccessHandler);
        adminUsernamePasswordAuthenticationFilter.setAuthenticationFailureHandler(adminAuthenticationFailureHandler);

        //注入过滤器,addFilterAt替换UsernamePasswordAuthenticationFilter
        http.addFilterAt(adminUsernamePasswordAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(adminAuthenticationTokenFilter,AdminUsernamePasswordAuthenticationFilter.class);
    }


}
