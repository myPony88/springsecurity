package com.example.springsecuritydemo1.common.exception;

import lombok.Data;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/7 18:16
 */
@Data
public class ServiceException extends RuntimeException {
    private Integer code;
    private String msg;

    public ServiceException(Integer code, String msg) {
        super(msg);
        this.code = code;
        this.msg = msg;
    }

    public ServiceException(String msg) {
        super(msg);
        this.code = 500;
        this.msg = msg;
    }

}
