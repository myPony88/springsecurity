package com.example.springsecuritydemo1.user.service.impl;

import com.example.springsecuritydemo1.user.entity.SysMenu;
import com.example.springsecuritydemo1.user.mapper.SysMenuMapper;
import com.example.springsecuritydemo1.user.service.ISysMenuService;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import org.springframework.stereotype.Service;

/**
 * <p>
 * 菜单表 服务实现类
 * </p>
 *
 * @author myh
 * @since 2023-02-20
 */
@Service
public class SysMenuServiceImpl extends ServiceImpl<SysMenuMapper, SysMenu> implements ISysMenuService {

}
