package com.tiger.common.utils;

import org.jasypt.encryption.StringEncryptor;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

import java.security.SecureRandom;
import java.util.Base64;

public final class JasyptUtil {
    public static StringEncryptor stringEncryptor(String password) {
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setAlgorithm("PBEWithMD5AndDES");
        config.setKeyObtentionIterations("1000");
        config.setPoolSize("1");
        config.setProviderName("SunJCE");
        config.setSaltGeneratorClassName("org.jasypt.salt.RandomSaltGenerator");
        config.setStringOutputType("base64");
        encryptor.setConfig(config);
        return encryptor;
    }

    public static void main(String[] args) {
        SecureRandom random = new SecureRandom();
        byte[] secretBytes = new byte[64]; // 32 bytes = 256 bits
        random.nextBytes(secretBytes);
        String secret = Base64.getEncoder().encodeToString(secretBytes);
        System.out.println(secret);
    }
}
