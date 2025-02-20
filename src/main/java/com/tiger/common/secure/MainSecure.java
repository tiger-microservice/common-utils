package com.tiger.common.secure;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.jasypt.encryption.pbe.PooledPBEStringEncryptor;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.text.BasicTextEncryptor;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class MainSecure {

    public static void main(String[] args) {
        pgpEncryptAndDecrypt();
//        digitalSignature();
//        signDataWithBouncyCastleCrypto();
//        jasypt();
//        genPassword();
//        genPasswordV2();
    }

    private static void jasypt() {
        BasicTextEncryptor textEncryptor = new BasicTextEncryptor();
        String privateData = "secret-data";
        textEncryptor.setPasswordCharArray("some-random-data".toCharArray());

        // when
        String myEncryptedText = textEncryptor.encrypt(privateData);
        System.out.println(myEncryptedText); // myEncryptedText can be save in db

        // then
        String plainText = textEncryptor.decrypt(myEncryptedText);
        System.out.println(plainText);
    }

    private static void genPassword() {
        String password = "secret-pass";
        BasicPasswordEncryptor passwordEncryptor = new BasicPasswordEncryptor();
        String encryptedPassword = passwordEncryptor.encryptPassword(password);
        System.out.println(encryptedPassword);

        // when
        boolean result = passwordEncryptor.checkPassword("secret-pass", encryptedPassword);
        System.out.println(result);
    }

    private static void genPasswordV2() {
        // given
        String privateData = "secret-data";
        PooledPBEStringEncryptor encryptor = new PooledPBEStringEncryptor();
        encryptor.setPoolSize(4);
        encryptor.setPassword("some-random-data");
        encryptor.setAlgorithm("PBEWithMD5AndTripleDES");

        // when
        String encryptedText = encryptor.encrypt(privateData);
        System.out.println(encryptedText);

        // then
        String plainText = encryptor.decrypt(encryptedText);
        System.out.println(plainText);
    }

    private static void signDataWithBouncyCastleCrypto() {
        try {
            String certificatePath = "/Users/tigerpro/Library/Mobile Documents/com~apple~CloudDocs/Documents/SA/shop-dev/microservice-java/common-utils/src/main/resources/bouncycastle/Baeldung.cer";
            String privateKeyPath = "/Users/tigerpro/Library/Mobile Documents/com~apple~CloudDocs/Documents/SA/shop-dev/microservice-java/common-utils/src/main/resources/bouncycastle/Baeldung.p12";
            char[] p12Password = "password".toCharArray();
            char[] keyPassword = "password".toCharArray();
            Security.addProvider(new BouncyCastleProvider());
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(new FileInputStream(certificatePath));
            KeyStore keystore = KeyStore.getInstance("PKCS12");
            keystore.load(new FileInputStream(privateKeyPath), p12Password);
            PrivateKey privateKey = (PrivateKey) keystore.getKey("baeldung", keyPassword);
            String secretMessage = "My password is 123456Seven";
            System.out.println("Original Message : " + secretMessage);
            byte[] stringToEncrypt = secretMessage.getBytes();

            // encrypt/decrypt
            byte[] encryptedData = BouncyCastleCryptoUtil.encryptData(stringToEncrypt, certificate);
            System.out.println(new String(encryptedData));
            byte[] rawData = BouncyCastleCryptoUtil.decryptData(encryptedData, privateKey);
            String decryptedMessage = new String(rawData);
            System.out.println(decryptedMessage.equals(secretMessage));

            // sign/verify
            byte[] signedData = BouncyCastleCryptoUtil.signData(rawData, certificate, privateKey);
            Boolean check = BouncyCastleCryptoUtil.verifySignData(signedData);
            System.out.println(check);
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println(e.getMessage());
        }
    }

    private static void digitalSignature() {
        String root = "/Users/tigerpro/Library/Mobile Documents/com~apple~CloudDocs/Documents/SA/shop-dev/microservice-java/";
        String messagePath = "/Users/tigerpro/Library/Mobile Documents/com~apple~CloudDocs/Documents/SA/shop-dev/microservice-java/common-utils/src/main/resources/digitalsignature/message.txt";
        String senderKeyStore = "/Users/tigerpro/Library/Mobile Documents/com~apple~CloudDocs/Documents/SA/shop-dev/microservice-java/common-utils/src/main/resources/digitalsignature/sender_keystore.jks";
        String receiverKeyStore = "/Users/tigerpro/Library/Mobile Documents/com~apple~CloudDocs/Documents/SA/shop-dev/microservice-java/common-utils/src/main/resources/digitalsignature/receiver_keystore.jks";
        String storeType = "JKS";
        String senderAlias = "senderKeyPair";
        String receiverAlias = "receiverKeyPair";
        char[] password = "changeit".toCharArray();
        String signingAlgorithm = "SHA256withRSA";
        String hashingAlgorithm = "SHA-256";

        try {
            PrivateKey privateKey = DigitalSignatureUtil.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
            byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

            byte[] digitalSignature = DigitalSignatureUtil.sign(messageBytes, signingAlgorithm, privateKey);

            PublicKey publicKey = DigitalSignatureUtil.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
            boolean isCorrect = DigitalSignatureUtil.verify(messageBytes, signingAlgorithm, publicKey, digitalSignature);
            System.out.println(isCorrect);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void whenSignWithSignatureSigning() {
        String messagePath = "src/resources/digitalsignature/message.txt";
        String senderKeyStore = "src/resources/digitalsignature/sender_keystore.jks";
        String receiverKeyStore = "src/resources/digitalsignature/receiver_keystore.jks";
        String storeType = "JKS";
        String senderAlias = "senderKeyPair";
        String receiverAlias = "receiverKeyPair";
        char[] password = "changeit".toCharArray();
        String signingAlgorithm = "SHA256withRSA";
        String hashingAlgorithm = "SHA-256";
        try {
            PrivateKey privateKey = DigitalSignatureUtil.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
            byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

            byte[] encryptedMessageHash = DigitalSignatureUtil.signWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, privateKey);

            PublicKey publicKey = DigitalSignatureUtil.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
            boolean isCorrect = DigitalSignatureUtil.verifyWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, publicKey, encryptedMessageHash);
            System.out.println(isCorrect);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void whenSignWithMessageDigestAndCipher() {
        String messagePath = "src/resources/digitalsignature/message.txt";
        String senderKeyStore = "src/resources/digitalsignature/sender_keystore.jks";
        String receiverKeyStore = "src/resources/digitalsignature/receiver_keystore.jks";
        String storeType = "JKS";
        String senderAlias = "senderKeyPair";
        String receiverAlias = "receiverKeyPair";
        char[] password = "changeit".toCharArray();
        String signingAlgorithm = "SHA256withRSA";
        String hashingAlgorithm = "SHA-256";
        try {
            PrivateKey privateKey = DigitalSignatureUtil.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
            byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

            byte[] encryptedMessageHash = DigitalSignatureUtil.signWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, privateKey);

            PublicKey publicKey = DigitalSignatureUtil.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
            boolean isCorrect = DigitalSignatureUtil.verifyWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, publicKey, encryptedMessageHash);
            System.out.println(isCorrect);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void thenVerifyWithMessageDigestAndCipher() {
        String messagePath = "src/resources/digitalsignature/message.txt";
        String senderKeyStore = "src/resources/digitalsignature/sender_keystore.jks";
        String receiverKeyStore = "src/resources/digitalsignature/receiver_keystore.jks";
        String storeType = "JKS";
        String senderAlias = "senderKeyPair";
        String receiverAlias = "receiverKeyPair";
        char[] password = "changeit".toCharArray();
        String signingAlgorithm = "SHA256withRSA";
        String hashingAlgorithm = "SHA-256";
        try {
            PrivateKey privateKey = DigitalSignatureUtil.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
            byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

            byte[] digitalSignature = DigitalSignatureUtil.sign(messageBytes, signingAlgorithm, privateKey);

            PublicKey publicKey = DigitalSignatureUtil.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
            boolean isCorrect = DigitalSignatureUtil.verifyWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, publicKey, digitalSignature);
            System.out.println(isCorrect);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void whenSignWithMessageDigestAndCipher_thenVerifyWithSignature() {
        String messagePath = "src/resources/digitalsignature/message.txt";
        String senderKeyStore = "src/resources/digitalsignature/sender_keystore.jks";
        String receiverKeyStore = "src/resources/digitalsignature/receiver_keystore.jks";
        String storeType = "JKS";
        String senderAlias = "senderKeyPair";
        String receiverAlias = "receiverKeyPair";
        char[] password = "changeit".toCharArray();
        String signingAlgorithm = "SHA256withRSA";
        String hashingAlgorithm = "SHA-256";
        try {
            PrivateKey privateKey = DigitalSignatureUtil.getPrivateKey(senderKeyStore, password, storeType, senderAlias);
            byte[] messageBytes = Files.readAllBytes(Paths.get(messagePath));

            byte[] encryptedMessageHash = DigitalSignatureUtil.signWithMessageDigestAndCipher(messageBytes, hashingAlgorithm, privateKey);

            PublicKey publicKey = DigitalSignatureUtil.getPublicKey(receiverKeyStore, password, storeType, receiverAlias);
            boolean isCorrect = DigitalSignatureUtil.verify(messageBytes, signingAlgorithm, publicKey, encryptedMessageHash);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void pgpEncryptAndDecrypt() {
        Path resourcesPath = Paths.get("common-utils", "src", "main", "resources");
        String pgpresource = resourcesPath.resolve("pgp")
                .toAbsolutePath()
                .toString();
        String pubKeyFileName = pgpresource + "/public_key.asc";
        String encryptedFileName = pgpresource + "/EncryptedOutputFile.pgp";
        String plainTextInputFileName = pgpresource + "/PlainTextInputFile.txt";
        String privKeyFileName = pgpresource + "/private_key.asc";

        try {
//            PgpEncryptUtil.encryptFile(encryptedFileName, plainTextInputFileName, pubKeyFileName, true);
            PgpEncryptUtil.encrypt(new BufferedInputStream(new FileInputStream(plainTextInputFileName)),
                    new BufferedOutputStream(new FileOutputStream(encryptedFileName)),
                    new BufferedInputStream(new FileInputStream(pubKeyFileName)));
            long id = System.currentTimeMillis();
            PgpDecryptUtil.decryptFile(encryptedFileName, privKeyFileName, "baeldung".toCharArray(), "decryptedFile" + id + ".txt");
            System.out.println("DONE");
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }
}
