package com.tiger.common.secure;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.security.SecureRandom;
import java.security.Security;

public class PgpEncryptUtil {

    public static void encryptFile(String outputFileName, String inputFileName,
                                   String pubKeyFileName, boolean armor)
            throws IOException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        if (armor) {
            in = new ArmoredInputStream(in);
        }
        InputStream publicKeyStream = new BufferedInputStream(new FileInputStream(pubKeyFileName));
        encrypt(in, out, publicKeyStream);
        out.close();
    }

    public static void encrypt(InputStream inputStream, OutputStream outputStream, InputStream publicKeyStream) {
        Security.addProvider(new BouncyCastleProvider());
        try {
            PGPPublicKey encKey = PGPCoreUtil.readPublicKey(publicKeyStream);
            byte[] bytes = PGPCoreUtil.compressFile(inputStream, CompressionAlgorithmTags.ZIP);
            encrypt(outputStream, encKey, bytes);
        } catch (PGPException e) {
            System.out.println(e.getMessage());
            throw new RuntimeException(e);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static void encrypt(OutputStream outputStream, PGPPublicKey encKey, byte[] bytes) throws IOException, PGPException {
        PGPDataEncryptorBuilder encryptorBuilder = new JcePGPDataEncryptorBuilder(PGPEncryptedData.AES_256) // CAST5
                .setProvider("BC")
                .setSecureRandom(new SecureRandom())
                .setWithIntegrityPacket(true);
        PGPEncryptedDataGenerator encGen = new PGPEncryptedDataGenerator(encryptorBuilder);
        encGen.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));
        OutputStream cOut = encGen.open(outputStream, bytes.length);
        cOut.write(bytes);
        cOut.close();
    }
}
