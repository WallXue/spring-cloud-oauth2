package com.xue.resourceserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.web.bind.annotation.CrossOrigin;

/**
 * @author Xuewu
 * @date 2019/2/15
 */
@Configuration
@EnableResourceServer
public class SecurityConfiguration extends ResourceServerConfigurerAdapter {

    private static final String SOURCE_ID = "order";

    @Autowired
    private RedisConnectionFactory redisConnectionFactory;

    @Override
    @CrossOrigin
    public void configure(ResourceServerSecurityConfigurer resources) {
        resources.resourceId(SOURCE_ID).stateless(true);
        resources.tokenServices(defaultTokenServices());
    }

    /**
     * 创建一个默认的资源服务token
     */
    @Bean
    public ResourceServerTokenServices defaultTokenServices() {
        final DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        // 使用自定义的Token转换器
        defaultTokenServices.setTokenEnhancer(accessTokenConverter());
        // 使用自定义的tokenStore
        defaultTokenServices.setTokenStore(tokenStore());
        return defaultTokenServices;
    }

    String publicKey="-----BEGIN PUBLIC KEY-----" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4irSNcR7CSSfXconxL4" +
            "g4M4j34wTWdTv93ocMn4VmdB7rCBU/BlxXtBUf/cgLIgQhQrAPszSZSmxiEXCOkG" +
            "Pr4aQBQuPgmNIR95Dhbzw/ZN0BnecAt3ZfkkDBHv8kH3kR/jYGTdwrxKeDgXGljN" +
            "sTRhbjuASxPG/Z6gU1yRPCsgc2r8NYnztWGcDWqaobqjG3/yzFmusoAboyV7asIp" +
            "o4yk378LmonDNwxnOOTb2Peg5PeelwfOwJPbftK1VOOt18zA0cchw6dHUzq9NlB8" +
            "clps/VdBap9BxU3/0YoFXRIc18nyzrWo2BcY2KQqX//AJC3OAfrfDmo+BGK8E0mp" +
            "8wIDAQAB" +
            "-----END PUBLIC KEY-----";

    // Token转换器
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        //rsa 加密
//        accessTokenConverter.setVerifierKey(publicKey);

        //对称加密
//        accessTokenConverter.setSigningKey("SigningKey");

        return accessTokenConverter;
    }

    // 自定义的Token存储器，存到Redis中
    @Bean
    public TokenStore tokenStore() {
        RedisTokenStore tokenStore = new RedisTokenStore(redisConnectionFactory);
        return tokenStore;
    }

    /**
     * jwt 保存key
     * @return
     */
//    @Bean
//    public TokenStore tokenStore() {
//        JwtTokenStore jwtTokenStore = new JwtTokenStore(accessTokenConverter());
//        return jwtTokenStore;
//    }


    @Override
    public void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/sc/**").authenticated()
                .anyRequest().permitAll();
    }
}
