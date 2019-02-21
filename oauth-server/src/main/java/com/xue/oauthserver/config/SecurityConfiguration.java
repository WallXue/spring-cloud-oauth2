package com.xue.oauthserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

/**
 * @author Xuewu
 * @date 2019/2/15
 */
@Configuration
@EnableWebSecurity
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    //配置用户认证 用户查询模块
    @Autowired
    public void globalUserDetails(AuthenticationManagerBuilder auth) throws Exception {
        // 配置用户来源于数据库
        // 配置密码加密方式  BCryptPasswordEncoder，添加用户加密的时候请也用这个加密
        auth.userDetailsService(userDetailsService()).passwordEncoder(new BCryptPasswordEncoder());
    }

    /**
     * 用户加载模块
     *
     * @return
     */
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {

        // 这里是添加两个用户到内存中去，实际中是从#下面去通过数据库判断用户是否存在
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();

        BCryptPasswordEncoder passwordEncode = new BCryptPasswordEncoder();
        String pwd = passwordEncode.encode("123456");
        manager.createUser(User.withUsername("user_1").password(pwd).authorities("A1102","B332").roles("admin").build());
        manager.createUser(User.withUsername("user_2").password(pwd).authorities("USER").build());
        return manager;

        // #####################实际开发中在下面写从数据库获取数据###############################
        // return new UserDetailsService() {
        // @Override
        // public UserDetails loadUserByUsername(String username) throws
        // UsernameNotFoundException {
        // // 通过用户名获取用户信息
        // boolean isUserExist = false;
        // if (isUserExist) {
        // //创建spring security安全用户和对应的权限（从数据库查找）
        // User user = new User("username", "password",
        // AuthorityUtils.createAuthorityList("admin", "manager"));
        // return user;
        // } else {
        // throw new UsernameNotFoundException("用户[" + username + "]不存在");
        // }
        // }
        // };

    }


    /**
     * 配置拦截路径
     *
     * @param http
     * @throws Exception
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
//        http.requestMatchers().anyRequest().and().authorizeRequests().antMatchers("/oauth/**").permitAll();
        http.authorizeRequests().antMatchers("/oauth/**").permitAll();
    }


}
