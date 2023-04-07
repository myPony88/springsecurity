package com.example.springsecuritydemo1.springsecurity.component;

import com.example.springsecuritydemo1.common.exception.ServiceException;
import com.example.springsecuritydemo1.springsecurity.dto.SysUserDTO;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.util.Objects;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/7 10:17
 */
@Component
public class HttpRequestComponent {

    /**
     * 获取token
     */
    public String getToken(){
        HttpServletRequest request = ((ServletRequestAttributes) Objects.requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();
        String token = request.getHeader("token");
        if (StringUtils.isEmpty(token)) {
            throw new ServiceException("授权令牌为空");
        }
        return token;
    }

    /**
     * 获取用户信息
     */
    public SysUserDTO getAdminUserInfo(){
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SysUserDTO userDetialsDTO = (SysUserDTO) authentication.getPrincipal();
        if (Objects.isNull(userDetialsDTO)){
            throw new ServiceException(10000,"登录失效，请重新登录");
        }

        return userDetialsDTO;
    }

    /**
     * 获取用户ID
     */
    public Long getAdminUserId(){
        if (Objects.isNull(this.getAdminUserInfo().getSysUser())){
            throw new ServiceException(10000,"登录失效，请重新登录");
        }
        return this.getAdminUserInfo().getSysUser().getId();
    }
}
