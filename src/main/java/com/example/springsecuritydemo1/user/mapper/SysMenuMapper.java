package com.example.springsecuritydemo1.user.mapper;

import com.example.springsecuritydemo1.user.entity.SysMenu;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.apache.ibatis.annotations.Mapper;

/**
 * <p>
 * 菜单表 Mapper 接口
 * </p>
 *
 * @author myh
 * @since 2023-02-20
 */
@Mapper
public interface SysMenuMapper extends BaseMapper<SysMenu> {

}
