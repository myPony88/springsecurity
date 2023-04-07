package com.example.springsecuritydemo1.springsecurity.handler;

import cn.hutool.db.nosql.redis.RedisDS;
import cn.hutool.jwt.JWTUtil;
import com.alibaba.fastjson.JSON;
import com.example.springsecuritydemo1.common.util.ResultUtil;
import com.example.springsecuritydemo1.springsecurity.contant.RedisKey;
import com.example.springsecuritydemo1.springsecurity.contant.TokenHeader;
import com.example.springsecuritydemo1.springsecurity.dto.SysUserDTO;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import redis.clients.jedis.Jedis;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * @Description: 手机登录成功处理器
 * @Author: mayanhui
 * @Date: 2023/2/14 12:43
 */
@Component
public class MobileAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        //拿到登录用户信息
        SysUserDTO userDetails = (SysUserDTO)authentication.getPrincipal();

        //生成jwt
        Map<String, Object> map = new HashMap<>();
        map.put("uid", userDetails.getSysUser().getId());
        map.put("expire_time", System.currentTimeMillis() + 1000 * 60 * 60 * 24 * 15);
        String jwtToken = JWTUtil.createToken(map, "1234".getBytes());

        //将用户信息保存到redis
        Jedis jedis = RedisDS.create().getJedis();
        String key = RedisKey.MOBILE_USER_INFO + userDetails.getSysUser().getId().toString();
        jedis.set(key,JSON.toJSONString(userDetails));

        //当前token也保存到redis//单点登录
        jedis.set(RedisKey.MOBILE_USER_TOKEN + userDetails.getSysUser().getId().toString(),jwtToken);

        Map<String,Object> resultMap = new HashMap<>();
        resultMap.put("token", TokenHeader.MOBILE_TOKEN_PREFIX+jwtToken);

        //输出结果
        httpServletResponse.setCharacterEncoding("utf-8");
        httpServletResponse.setContentType("application/json");
        httpServletResponse.getWriter().write(JSON.toJSONString(ResultUtil.ok(resultMap)));
    }
}
