package com.example.springsecuritydemo1.common.util;

import lombok.Data;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/7 9:38
 */
@Data
public class ResultUtil<T> {
    private Integer code;
    private String message;
    private T data;

    public ResultUtil() {
        this.code = 200;
        this.message = "success";
    }

    public ResultUtil(Integer code, String msg) {
        this.code = code;
        this.message = msg;
    }

    public ResultUtil(Integer code, T data) {
        this.code = code;
        this.data = data;
    }

    public ResultUtil(T data) {
        this.code = 200;
        this.message = "success";
        this.data = data;
    }

    public static <T> ResultUtil<T> ok() {
        return new ResultUtil<T>();
    }

    public static <T> ResultUtil<T> ok(T data) {
        return new ResultUtil<T>(data);
    }

    public static <T> ResultUtil<T> ok(Integer code, String message) {
        return new ResultUtil<T>(code, message);
    }

    public static <T> ResultUtil<T> fail(String message) {
        return new ResultUtil<T>(500, message);
    }

    public static <T> ResultUtil<T> fail(Integer code, String message) {
        return new ResultUtil<T>(code, message);
    }
}
