package com.example.springsecuritydemo1.springsecurity.handler;

import com.alibaba.fastjson.JSON;
import com.example.springsecuritydemo1.common.util.ResultUtil;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Description: 后台登录失败处理器
 * @Author: mayanhui
 * @Date: 2023/2/14 12:43
 */
@Component
public class AdminAuthenticationFailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        //修改编码格式
        httpServletResponse.setCharacterEncoding("utf-8");
        httpServletResponse.setContentType("application/json");

        if (e instanceof BadCredentialsException){
            httpServletResponse.getWriter().write(JSON.toJSONString(ResultUtil.fail(1000,"用户名或密码错误")));
        }else {
            httpServletResponse.getWriter().write(JSON.toJSONString(ResultUtil.fail(1000,e.getMessage())));
        }

    }
}
