package com.tiger.common.secure;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.BCPGOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Date;
import java.util.Iterator;

public class PgpEncryptUtil {

    public static void encrypt(String outputFileName, String inputFileName,
                                   String pubKeyFileName, boolean armor)
            throws IOException, PGPException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(outputFileName));
        InputStream in = new BufferedInputStream(new FileInputStream(inputFileName));
        if (armor) {
            in = new ArmoredInputStream(in);
        }
        InputStream publicKeyStream = new BufferedInputStream(new FileInputStream(pubKeyFileName));
        encrypt(in, out, publicKeyStream);
        out.close();
    }

    public static void encryptAndSign(String message, String inputFileName) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        // hardcode our private key password **NOT A GOOD IDEA...duh**
        String privateKeyPassword = "hongkong";

        PGPPublicKey pubKey = null;
        // Load public key
        try {
            pubKey = PGPCoreUtil.readPublicKey(new FileInputStream(""));
        } catch (IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (pubKey != null) {
            System.out.println("Successfully read public key: ");
            // System.out.println("Key Owner: "+pubKey.getUserIDs());
            // System.out.println("Key Stength: "+pubKey.getBitStrength());
            // System.out.println("Key Algorithm: "+pubKey.getAlgorithm()+"\n\n");
        }

        // Load private key, **NOTE: still secret, we haven't unlocked it yet**
        PGPSecretKey pgpSec = null;
        try {
            pgpSec = PGPCoreUtil.readSecretKey(new FileInputStream(new File("")));
        } catch (IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        // sign our message
        String messageSignature = null;
        try {
            messageSignature = signMessageByteArray(messageSignature.getBytes(StandardCharsets.UTF_8),
                    pgpSec, privateKeyPassword);
        } catch (NoSuchAlgorithmException | NoSuchProviderException
                 | SignatureException | IOException | PGPException e) {
            e.printStackTrace();
        }

        if (messageSignature != null) {
            System.out
                    .println("Successfully signed your message with the private key.\n\n");
            System.out.println(messageSignature + "\n\n");
        }

        System.out.println("Now Encrypting it.");

        String encryptedMessage = null;
        BufferedOutputStream out = new BufferedOutputStream(null);
        try {
            // byte[] bytes, OutputStream outputStream, InputStream publicKeyStream
            encrypt(messageSignature.getBytes(StandardCharsets.UTF_8), out, new FileInputStream(""));
        } catch (IOException | PGPException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

        if (encryptedMessage != null) {
            System.out.println("PGP Encrypted Message: ");
            System.out.println(encryptedMessage);
        }
    }

    @SuppressWarnings("rawtypes")
    private static String signMessageByteArray(byte[] messageCharArray, PGPSecretKey pgpSec, String pass) throws IOException,
            NoSuchAlgorithmException, NoSuchProviderException, PGPException,
            SignatureException {

        ByteArrayOutputStream encOut = new ByteArrayOutputStream();
        OutputStream out = encOut;
        out = new ArmoredOutputStream(out);

        // Unlock the private key using the password
        PGPPrivateKey pgpPrivKey = pgpSec
                .extractPrivateKey(new JcePBESecretKeyDecryptorBuilder()
                        .setProvider("BC").build(pass.toCharArray()));

        // Signature generator, we can generate the public key from the private
        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(pgpSec.getPublicKey()
                        .getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));

        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        Iterator it = pgpSec.getPublicKey().getUserIDs();
        if (it.hasNext()) {
            PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
            spGen.setSignerUserID(false, (String) it.next());
            sGen.setHashedSubpackets(spGen.generate());
        }

        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(
                PGPCompressedData.ZLIB);

        BCPGOutputStream bOut = new BCPGOutputStream(comData.open(out));

        sGen.generateOnePassVersion(false).encode(bOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream lOut = lGen.open(bOut, PGPLiteralData.BINARY,
                PGPLiteralData.CONSOLE, messageCharArray.length, new Date());

        for (byte c : messageCharArray) {
            lOut.write(c);
            sGen.update(c);
        }

        lOut.close();
        lGen.close();
        sGen.generate().encode(bOut);
        comData.close();
        out.close();
        return encOut.toString();
    }

    public static void encrypt(InputStream inputStream, OutputStream outputStream, InputStream publicKeyStream)
            throws PGPException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        PGPPublicKey encKey = PGPCoreUtil.readPublicKey(publicKeyStream);
        byte[] bytes = PGPCoreUtil.compressFile(inputStream, CompressionAlgorithmTags.ZIP);
        encrypt(outputStream, encKey, bytes);
    }

    public static void encrypt(byte[] bytes, OutputStream outputStream, InputStream publicKeyStream)
            throws PGPException, IOException {
        Security.addProvider(new BouncyCastleProvider());
        PGPPublicKey encKey = PGPCoreUtil.readPublicKey(publicKeyStream);
        encrypt(outputStream, encKey, bytes);
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
