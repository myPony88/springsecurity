package com.example.springsecuritydemo1.springsecurity.service;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author mayanhui
 */
public interface BaseUserDetailsService extends UserDetailsService {

    /**
     *手机号登录
     */
    UserDetails loadUserByPhone(String phone) throws UsernameNotFoundException;

    /**
     *微信
     */
    UserDetails loadUserByAppId(String appId) throws UsernameNotFoundException;

}
