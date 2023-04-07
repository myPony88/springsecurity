package com.example.springsecuritydemo1.springsecurity.config;

import com.example.springsecuritydemo1.springsecurity.filter.AdminAuthenticationTokenFilter;
import com.example.springsecuritydemo1.springsecurity.filter.AdminUsernamePasswordAuthenticationFilter;
import com.example.springsecuritydemo1.springsecurity.filter.MobileAuthenticationFilter;
import com.example.springsecuritydemo1.springsecurity.filter.MobileAuthenticationTokenFilter;
import com.example.springsecuritydemo1.springsecurity.handler.AdminAuthenticationFailureHandler;
import com.example.springsecuritydemo1.springsecurity.handler.AdminAuthenticationSuccessHandler;
import com.example.springsecuritydemo1.springsecurity.handler.MobileAuthenticationFailureHandler;
import com.example.springsecuritydemo1.springsecurity.handler.MobileAuthenticationSuccessHandler;
import com.example.springsecuritydemo1.springsecurity.provider.MobileAuthenticationProvider;
import com.example.springsecuritydemo1.springsecurity.service.BaseUserDetailsService;
import com.example.springsecuritydemo1.springsecurity.service.impl.UserDetailServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

/**
 * @Description: 手机号登录过滤器注入配置
 * @Author: mayanhui
 * @Date: 2023/2/14 12:43
 */
@Component
public class SpringSecurityMobileConfig extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {

    @Autowired
    UserDetailServiceImpl userDetailService;

    @Autowired
    MobileAuthenticationSuccessHandler mobileAuthenticationSuccessHandler;

    @Autowired
    MobileAuthenticationFailureHandler mobileAuthenticationFailureHandler;

    @Autowired
    MobileAuthenticationTokenFilter mobileAuthenticationTokenFilter;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        MobileAuthenticationFilter mobileAuthenticationFilter = new MobileAuthenticationFilter();
        mobileAuthenticationFilter.setAuthenticationManager(http.getSharedObject(AuthenticationManager.class));
        mobileAuthenticationFilter.setAuthenticationSuccessHandler(mobileAuthenticationSuccessHandler);
        mobileAuthenticationFilter.setAuthenticationFailureHandler(mobileAuthenticationFailureHandler);

        //new一个mobileAuthenticationProvider
        MobileAuthenticationProvider mobileAuthenticationProvider = new MobileAuthenticationProvider();
        mobileAuthenticationProvider.setBaseUserDetailsService(userDetailService);

        //注入过滤器
        http.authenticationProvider(mobileAuthenticationProvider)
                .addFilterAfter(mobileAuthenticationFilter,AdminUsernamePasswordAuthenticationFilter.class)
                .addFilterBefore(mobileAuthenticationTokenFilter,MobileAuthenticationFilter.class);
    }

}
