package com.example.springsecuritydemo1.springsecurity.service.impl;

import com.baomidou.mybatisplus.core.conditions.query.LambdaQueryWrapper;
import com.example.springsecuritydemo1.common.exception.ServiceException;
import com.example.springsecuritydemo1.springsecurity.dto.SysUserDTO;
import com.example.springsecuritydemo1.springsecurity.service.BaseUserDetailsService;
import com.example.springsecuritydemo1.user.entity.SysMenu;
import com.example.springsecuritydemo1.user.entity.SysUser;
import com.example.springsecuritydemo1.user.mapper.SysUserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.List;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/21 15:49
 */
@Service
public class UserDetailServiceImpl implements BaseUserDetailsService {
    @Autowired
    SysUserMapper sysUserMapper;

    @Override
    public SysUserDTO loadUserByUsername(String username) throws UsernameNotFoundException {
        //用户信息
        LambdaQueryWrapper<SysUser> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(SysUser::getUserName, username);
        List<SysUser> sysUsers = sysUserMapper.selectList(wrapper);
        if (CollectionUtils.isEmpty(sysUsers)){
            throw new ServiceException("该用户不存在");
        }

        //获取权限信息
        List<SysMenu> userHasMenu = sysUserMapper.getUserHasMenu(sysUsers.get(0).getId());

        return new SysUserDTO(sysUsers.get(0),userHasMenu);
    }

    @Override
    public SysUserDTO loadUserByPhone(String phone) throws UsernameNotFoundException {
        //用户信息
        LambdaQueryWrapper<SysUser> wrapper = new LambdaQueryWrapper<>();
        wrapper.eq(SysUser::getPhone, phone);
        List<SysUser> sysUsers = sysUserMapper.selectList(wrapper);
        if (CollectionUtils.isEmpty(sysUsers)){
            throw new ServiceException("该用户不存在");
        }
        return new SysUserDTO(sysUsers.get(0),null);
    }

    @Override
    public UserDetails loadUserByAppId(String appId) throws UsernameNotFoundException {
        return null;
    }


}
