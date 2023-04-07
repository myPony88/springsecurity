package com.example.springsecuritydemo1.user.service.impl;

import com.example.springsecuritydemo1.user.entity.SysRole;
import com.example.springsecuritydemo1.user.mapper.SysRoleMapper;
import com.example.springsecuritydemo1.user.service.ISysRoleService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 角色表 服务实现类
 * </p>
 *
 * @author myh
 * @since 2023-02-20
 */
@Service
public class SysRoleServiceImpl extends ServiceImpl<SysRoleMapper, SysRole> implements ISysRoleService {

}
