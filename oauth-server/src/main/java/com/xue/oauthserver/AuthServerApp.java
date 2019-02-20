package com.xue.oauthserver;

import org.apache.commons.codec.binary.Base64;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.security.*;

/**
 * @author Xuewu
 * @date 2019/2/15
 */

@SpringBootApplication
public class AuthServerApp {

    public static void main(String[] args) {
        SpringApplication.run(AuthServerApp.class, args);
    }

//    public static void main(String[] args) throws NoSuchAlgorithmException {
//        KeyPairGenerator keyPairGenerator = KeyPairGenerator
//                .getInstance("RSA");
//        KeyPair keyPair = keyPairGenerator.generateKeyPair();
//        PrivateKey privateKey = keyPair.getPrivate();
//        PublicKey publicKey = keyPair.getPublic();
//        System.out.println(new String(Base64.encodeBase64(privateKey.getEncoded())));
//        System.out.println();
//        System.out.println(new String(Base64.encodeBase64(publicKey.getEncoded())));
//    }
}
