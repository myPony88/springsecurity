package com.example.springsecuritydemo1.common.exception;

import com.example.springsecuritydemo1.common.util.ResultUtil;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/7 18:13
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ResultUtil<Void> error(Exception e) {
        return ResultUtil.fail(e.getMessage());
    }

    @ExceptionHandler(ServiceException.class)
    @ResponseBody
    public ResultUtil<Void> serviceException(ServiceException e) {
        return ResultUtil.fail(e.getCode(), e.getMsg());
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResultUtil<Void> accessDeniedException(AccessDeniedException e) throws AccessDeniedException {
        return ResultUtil.fail(403, "没有权限访问");
    }
}
