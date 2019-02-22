package com.xue.oauthserver.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author Xuewu
 * @date 2019/2/15
 */
@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {
    //token有效时间 秒   30分钟
    private static final int ACCESS_TOKEN_TIMER = 60 * 30;
    //刷新token有效时间 秒   2天
    private static final int REFRESH_TOKEN_TIMER = 60 * 60 * 24 * 2;


    //key 长度会影响    报名加密大小
    String privateKey = "-----BEGIN RSA PRIVATE KEY-----" +
            "MIIEowIBAAKCAQEAm4irSNcR7CSSfXconxL4g4M4j34wTWdTv93ocMn4VmdB7rCB" +
            "U/BlxXtBUf/cgLIgQhQrAPszSZSmxiEXCOkGPr4aQBQuPgmNIR95Dhbzw/ZN0Bne" +
            "cAt3ZfkkDBHv8kH3kR/jYGTdwrxKeDgXGljNsTRhbjuASxPG/Z6gU1yRPCsgc2r8" +
            "NYnztWGcDWqaobqjG3/yzFmusoAboyV7asIpo4yk378LmonDNwxnOOTb2Peg5Pee" +
            "lwfOwJPbftK1VOOt18zA0cchw6dHUzq9NlB8clps/VdBap9BxU3/0YoFXRIc18ny" +
            "zrWo2BcY2KQqX//AJC3OAfrfDmo+BGK8E0mp8wIDAQABAoIBAENp64P45GXMPEpx" +
            "eYPpfxnRqJRZh6olHSHOl087243n16YTjxrI2fPMxrU6B2Mo0d6SS0lzl/lOmzLJ" +
            "aOiNyA0t7MbVeG2fSjKPJ7M5s5K+kV+fttAtyCTE5iDtLWl9ukaG4dEIJy6e2lBd" +
            "T3Y2A4HJSGm1FJh2DAwl0ywOtUy0X6ki9DgXVAaCGDuoU25Rhun64dh802DZbEEJ" +
            "LdorIyeJ0ovCZyNvhlZRYkAOPy3k88smYl2jE/AbZ7pCKz/XggDcjNsERm2llaa3" +
            "pNTAZQUlHu0BQrCn6J9BxtMPyduiyrE+JYqTwnYhWQ5QRe/2J8O3t0eIK9TfUQpJ" +
            "DrZf00ECgYEAy/sLX8UCmERwMuaQSwoM0BHTZIc0iAsgiXbVOLua9I3Tu/mXOVdH" +
            "TikjdoWLqM62bA9dN/oqzHDwvqCy6zwamjFVSmJUejf5v+52Qj64leOmDX/RC4ne" +
            "L08N1nP/Y4X24Y/5zq18qvVlhOMDdydzayJFrGhkQKhJg58pRUIdenECgYEAwzLC" +
            "Awr3LeUlHa+d2O6siJVmljTc8lT+qX4TvqTDH8rAC/EyKMNaTjaX6mWosZZ7qYXv" +
            "EMxvQzTEzUHRXrCGlhbX8xiBlWnvpghF2GJEvP9WaU/+OCr0gItRSLPDuZ6ctzKb" +
            "3QkBEiC8ODyPRKzlA67D23S3KJB067IUV81h9KMCgYBXUqmT3is2NFYz9DBhb3P8" +
            "vyTYLGl4tArBznWJTAcSGoVCO59ZlNuZwlLEMnePVK8To6AsjpQz4UWu1ezCd4CL" +
            "8gKpTV8M01m/qL5HrcInqMU1kjpTzjmn1xf9brsuR/NgrNoseGieZ1+GfAjHwcPP" +
            "YWSiYi5I38JY7pIkbCFigQKBgAnVtty8YrPXRcV3IbbaX6sKC/8pbrBvA926Unha" +
            "iNJDPuXbIzHWleg26/SNZrB76oMiEmeARWLXd8r3s/rXXhCV2g+PfofurHprFEnQ" +
            "ubHkE5B+zUo7L9KCMng9RnFFwpOgYyYB3CHzsEgNFRLauzcySP/3o3rRvHJbqJa7" +
            "7GGNAoGBAKSBn4zq0iNWI2BUBb90icMsHEneiydGtFcEl3/Sz8vmjFZn0sjRbGoY" +
            "gmP9LlQ+o7xRiJ/LTesi5BA6zCGrcdp0aeyJzCRbFc3WqjGeyLbfx1sJVVB6PnvS" +
            "iKvvCOJq6kl3/opO+ybqJ8dzkEyoj8K4+fcX1+U6eW2w+vSpOosG" +
            "-----END RSA PRIVATE KEY-----";

    String publicKey = "-----BEGIN PUBLIC KEY-----" +
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAm4irSNcR7CSSfXconxL4" +
            "g4M4j34wTWdTv93ocMn4VmdB7rCBU/BlxXtBUf/cgLIgQhQrAPszSZSmxiEXCOkG" +
            "Pr4aQBQuPgmNIR95Dhbzw/ZN0BnecAt3ZfkkDBHv8kH3kR/jYGTdwrxKeDgXGljN" +
            "sTRhbjuASxPG/Z6gU1yRPCsgc2r8NYnztWGcDWqaobqjG3/yzFmusoAboyV7asIp" +
            "o4yk378LmonDNwxnOOTb2Peg5PeelwfOwJPbftK1VOOt18zA0cchw6dHUzq9NlB8" +
            "clps/VdBap9BxU3/0YoFXRIc18nyzrWo2BcY2KQqX//AJC3OAfrfDmo+BGK8E0mp" +
            "8wIDAQAB" +
            "-----END PUBLIC KEY-----";

    AuthenticationManager authenticationManager;

    @Autowired
    RedisConnectionFactory redisConnectionFactory;


    public AuthServerConfig(
            AuthenticationConfiguration authenticationConfiguration
    ) throws Exception {
        this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
    }


    /**
     * 配置auth server 基本信息
     *
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient("myapp")//（必填）客户端ID。
//                .resourceIds(SOURCE_ID)
                .authorizedGrantTypes("password", "refresh_token")//授予客户端使用授权的类型。默认值为空。
                .scopes("all")//客户受限的范围。如果范围未定义或为空（默认值），客户端不受范围限制。read write all
//                .authorities("ADMIN")//授予客户的授权机构（普通的Spring Security权威机构）。
                .secret("{noop}")//(可信客户端需要）客户机密码（如果有）。没有可不填。加密需要配置passwordEncoder
                .accessTokenValiditySeconds(ACCESS_TOKEN_TIMER)
                .refreshTokenValiditySeconds(REFRESH_TOKEN_TIMER)
        ;
    }

    /**
     * 配置token生成规则，保存方式，登录认证方式
     *
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(userTokenEnhancer(), accessTokenConverter()));

        endpoints.tokenEnhancer(tokenEnhancerChain);//token主体中用户信息补充
        endpoints.accessTokenConverter(accessTokenConverter());
        endpoints.tokenStore(tokenStore());
        endpoints.authenticationManager(authenticationManager);
        endpoints.reuseRefreshTokens(false);//false ：刷新token可以重新续，（刷完一次后返回的刷新token还可以无限刷下去，在刷新token有效期内用户可以永远不用登陆） true:用户密码登陆一次后刷新token可以用一次，刷新时返回的token不再可用
//        endpoints.pathMapping("/oauth/authorize", "/abc/");  替换默认URL路径
    }

    /**
     * 配置auth server 参数
     *
     * @param oauthServer
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {

        oauthServer.allowFormAuthenticationForClients();// 允许表单认证
        oauthServer.tokenKeyAccess("permitAll()");//开放token_key url 客户端获取jwt公钥
        oauthServer.checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");//check_token 接口开放  以便资源服务可以进行访问
//        oauthServer.passwordEncoder(new BCryptPasswordEncoder());//secret 加密用
    }

    // JWT 生成器
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
        // 测试用,资源服务使用相同的字符达到一个对称加密的效果,生产时候使用RSA非对称加密方式

        //对称加密
//        accessTokenConverter.setSigningKey("SigningKey");

        //RSA加密
        accessTokenConverter.setSigningKey(privateKey);
        accessTokenConverter.setVerifierKey(publicKey);
        return accessTokenConverter;
    }

    /**
     * 用户信息补充
     *
     * @return
     */
    @Bean
    public TokenEnhancer userTokenEnhancer() {
        return (accessToken, authentication) -> {
            String userName = authentication.getUserAuthentication().getName();
            // 得到用户名，去处理数据库可以拿到当前用户的信息和角色信息（需要传递到服务中用到的信息）
            final Map<String, Object> additionalInformation = new HashMap<>();
            // Map假装用户实体
            Map<String, String> userinfo = new HashMap<>();
            userinfo.put("id", "1");
            userinfo.put("username", userName);
            userinfo.put("userFlag", "1");
            additionalInformation.put("userinfo", userinfo);
            ((DefaultOAuth2AccessToken) accessToken).setAdditionalInformation(additionalInformation);
            return accessToken;
        };
    }

    /**
     * redis key 保存
     *
     * @return
     */
    @Bean
    public TokenStore tokenStore() {
        RedisTokenStore tokenStore = new RedisTokenStore(redisConnectionFactory);
        return tokenStore;
    }

    /**
     *  jwt token 保存
     * @return
     */
//    @Bean
//    public TokenStore tokenStore() {
//        JwtTokenStore jwtTokenStore = new JwtTokenStore(accessTokenConverter());
//        return jwtTokenStore;
//    }


}
