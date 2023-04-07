package com.example.springsecuritydemo1.user.mapper;

import com.example.springsecuritydemo1.user.entity.SysMenu;
import com.example.springsecuritydemo1.user.entity.SysUser;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;

/**
 * <p>
 * 用户表 Mapper 接口
 * </p>
 *
 * @author myh
 * @since 2023-02-20
 */
@Mapper
public interface SysUserMapper extends BaseMapper<SysUser> {
    List<SysMenu> getUserHasMenu(Long id);
}
