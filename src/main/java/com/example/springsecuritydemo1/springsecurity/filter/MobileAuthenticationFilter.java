package com.example.springsecuritydemo1.springsecurity.filter;

import cn.hutool.db.nosql.redis.RedisDS;
import com.example.springsecuritydemo1.springsecurity.contant.RedisKey;
import com.example.springsecuritydemo1.springsecurity.token.MobileAuthenticationToken;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import redis.clients.jedis.Jedis;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/20 18:48
 */
public class MobileAuthenticationFilter extends AbstractAuthenticationProcessingFilter {
    //手机号
    public static final String SPRING_SECURITY_MOBILE_KEY = "mobile";
    //验证码
    public static final String SPRING_SECURITY_CODE_KEY  = "code";

    //改成手机号登录地址
    private static final AntPathRequestMatcher DEFAULT_ANT_PATH_REQUEST_MATCHER = new AntPathRequestMatcher("/mobile/login", "POST");

    private String mobileParameter = SPRING_SECURITY_MOBILE_KEY;

    private String codeParameter = SPRING_SECURITY_CODE_KEY;

    private boolean postOnly = true;

    public MobileAuthenticationFilter() {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER);
    }

    public MobileAuthenticationFilter(AuthenticationManager authenticationManager) {
        super(DEFAULT_ANT_PATH_REQUEST_MATCHER, authenticationManager);
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        if (postOnly && !request.getMethod().equals(HttpMethod.POST.name())) {
            throw new AuthenticationServiceException(
                    "Authentication method not supported: " + request.getMethod());
        }

        String mobile = obtainMobile(request);
        if (mobile == null) {
            mobile = "";
        }
        mobile = mobile.trim();

        String code = obtainCode(request);
        if (!StringUtils.hasLength(code)){
            throw new AuthenticationServiceException("Verification Code is empty");
        }
                
        Jedis jedis = RedisDS.create().getJedis();
        if (!code.equals(jedis.get(RedisKey.MOBILE_VERIFY_CODE+mobile))){
            throw new AuthenticationServiceException("Verification Code is error");
        }

        //生产一个手机号验证令牌
        MobileAuthenticationToken mobileAuthenticationToken = new MobileAuthenticationToken(mobile);
        setDetails(request, mobileAuthenticationToken);

        return this.getAuthenticationManager().authenticate(mobileAuthenticationToken);
    }

    @Nullable
    protected String obtainMobile(HttpServletRequest request) {
        return request.getParameter(this.mobileParameter);
    }

    @Nullable
    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(this.codeParameter);
    }

    protected void setDetails(HttpServletRequest request, MobileAuthenticationToken authRequest) {
        authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));
    }

    public void setCodeParameter(String codeParameter) {
        Assert.hasText(codeParameter, "code parameter must not be empty or null");
        this.codeParameter = codeParameter;
    }

    public void setMobileParameter(String mobileParameter) {
        Assert.hasText(mobileParameter, "Mobile parameter must not be empty or null");
        this.mobileParameter = mobileParameter;
    }

    public void setPostOnly(boolean postOnly) {
        this.postOnly = postOnly;
    }

    public final String getPhoneParameter() {
        return this.mobileParameter;
    }

    public final String getCodeParameter() {
        return this.codeParameter;
    }
}
