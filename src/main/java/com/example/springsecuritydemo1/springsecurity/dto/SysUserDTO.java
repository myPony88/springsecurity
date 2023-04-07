package com.example.springsecuritydemo1.springsecurity.dto;

import com.alibaba.fastjson.annotation.JSONField;
import com.example.springsecuritydemo1.user.entity.SysMenu;
import com.example.springsecuritydemo1.user.entity.SysUser;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @Description:
 * @Author: mayanhui
 * @Date: 2023/2/21 18:56
 */
@Data
@NoArgsConstructor
public class SysUserDTO implements UserDetails {
    private SysUser sysUser;

    private List<SysMenu> sysMenu;

    //不进行序列化
    @JSONField(serialize = false)
    private List<GrantedAuthority> authorities = new ArrayList<>();

    public SysUserDTO(SysUser sysUser,List<SysMenu> menus){
        this.sysUser = sysUser;
        this.sysMenu = menus;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (!CollectionUtils.isEmpty(authorities)) {
            return authorities;
        }

        for (SysMenu menu : sysMenu) {
            String perms = menu.getPerms();
            if (StringUtils.hasLength(perms)) {
                SimpleGrantedAuthority simpleGrantedAuthority = new SimpleGrantedAuthority(menu.getPerms());
                authorities.add(simpleGrantedAuthority);
            }
        }
        return authorities;
    }

    @Override
    public String getPassword() {
        return this.sysUser.getPassword();
    }

    @Override
    public String getUsername() {
        return this.sysUser.getUserName();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
