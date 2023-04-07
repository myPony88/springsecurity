package com.example.springsecuritydemo1.user.controller;

import com.example.springsecuritydemo1.common.util.ResultUtil;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <p>
 * 用户表 前端控制器
 * </p>
 *
 * @author myh
 * @since 2023-02-20
 */
@RestController
@RequestMapping("/user/sysUser")
public class SysUserController {
    @GetMapping("/index")
    @PreAuthorize("hasAuthority('sysUser/list')")
    public ResultUtil<Void> index(){
        return ResultUtil.ok(200,"成功访问到用户列表");
    }
}
