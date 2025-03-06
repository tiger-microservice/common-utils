package com.tiger.common.test;

import com.tiger.common.secure.Base64Util;
import com.tiger.common.secure.EncryptionUtil;

import javax.crypto.SecretKey;
import java.security.KeyPair;

public class EndToEndEncryptionDemo {
    public static void main(String[] args) throws Exception {
        // 1. Tạo cặp khóa RSA cho người gửi và người nhận
        KeyPair senderKeyPair = EncryptionUtil.generateRSAKeyPair();
        KeyPair receiverKeyPair = EncryptionUtil.generateRSAKeyPair();

        // 2. Tin nhắn cần gửi
        String originalMessage = "Hello, this is a secret message!";
        System.out.println("Original Message: " + originalMessage);

        // 3. Người gửi tạo khóa AES ngẫu nhiên
        SecretKey aesKey = EncryptionUtil.generateAESKey();

        // 4. Người gửi mã hóa tin nhắn bằng AES
        byte[] encryptedMessage = EncryptionUtil.encryptWithAES(originalMessage.getBytes(), aesKey);
        System.out.println("Encrypted Message (Base64): " + Base64Util.toBase64(encryptedMessage));

        // 5. Người gửi mã hóa khóa AES bằng public key của người nhận
        byte[] encryptedAESKey = EncryptionUtil.encryptWithRSA(
                EncryptionUtil.secretKeyToBytes(aesKey),
                receiverKeyPair.getPublic()
        );
        System.out.println("Encrypted AES Key (Base64): " + Base64Util.toBase64(encryptedAESKey));

        // 6. Người nhận giải mã khóa AES bằng private key của mình
        byte[] decryptedAESKeyBytes = EncryptionUtil.decryptWithRSA(encryptedAESKey, receiverKeyPair.getPrivate());
        SecretKey decryptedAESKey = EncryptionUtil.bytesToSecretKey(decryptedAESKeyBytes);

        // 7. Người nhận sử dụng khóa AES để giải mã tin nhắn
        byte[] decryptedMessageBytes = EncryptionUtil.decryptWithAES(encryptedMessage, decryptedAESKey);
        String decryptedMessage = new String(decryptedMessageBytes);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}