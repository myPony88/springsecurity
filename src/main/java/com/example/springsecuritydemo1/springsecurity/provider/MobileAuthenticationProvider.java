package com.example.springsecuritydemo1.springsecurity.provider;

import com.example.springsecuritydemo1.springsecurity.dto.SysUserDTO;
import com.example.springsecuritydemo1.springsecurity.service.BaseUserDetailsService;
import com.example.springsecuritydemo1.springsecurity.service.impl.UserDetailServiceImpl;
import com.example.springsecuritydemo1.springsecurity.token.MobileAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.Objects;

/**
 * @Description: 手机录处理逻辑
 * @Author: mayanhui
 * @Date: 2023/2/14 17:20
 */
public class MobileAuthenticationProvider implements AuthenticationProvider {

    private UserDetailServiceImpl userDetailService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        MobileAuthenticationToken mobileAuthenticationToken = (MobileAuthenticationToken) authentication;

        SysUserDTO sysUserDTO = this.userDetailService.loadUserByPhone(mobileAuthenticationToken.getPrincipal().toString());

        if (Objects.isNull(sysUserDTO)){
            throw new BadCredentialsException("手机登录失败");
        }

        MobileAuthenticationToken authenticationToken = new MobileAuthenticationToken(sysUserDTO,sysUserDTO.getAuthorities());
        authenticationToken.setDetails(authenticationToken.getCredentials());

        return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return MobileAuthenticationToken.class.isAssignableFrom(authentication);
    }

    public void setBaseUserDetailsService(UserDetailServiceImpl userDetailsService){
        this.userDetailService = userDetailsService;
    }
}
