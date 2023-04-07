package com.example.springsecuritydemo1.user.service.impl;

import com.example.springsecuritydemo1.user.entity.SysUser;
import com.example.springsecuritydemo1.user.mapper.SysUserMapper;
import com.example.springsecuritydemo1.user.service.ISysUserService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 用户表 服务实现类
 * </p>
 *
 * @author myh
 * @since 2023-02-20
 */
@Service
public class SysUserServiceImpl extends ServiceImpl<SysUserMapper, SysUser> implements ISysUserService {

}
