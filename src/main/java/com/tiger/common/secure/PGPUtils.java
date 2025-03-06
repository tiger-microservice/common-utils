package com.tiger.common.secure;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.openpgp.operator.*;

import java.io.*;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

public class PGPUtils {

    // Encrypt and sign data
    public static void encryptAndSignFile(OutputStream out, String fileName, PGPPublicKey encKey,
                                          PGPSecretKey signKey, char[] pass, boolean armor, boolean withIntegrityCheck)
            throws IOException, PGPException {
        Security.addProvider(new BouncyCastleProvider());
        if (armor) {
            out = new ArmoredOutputStream(out);
        }

        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PGPCompressedDataGenerator comData = new PGPCompressedDataGenerator(PGPCompressedData.ZIP);

        PGPSignatureGenerator sGen = new PGPSignatureGenerator(
                new JcaPGPContentSignerBuilder(signKey.getPublicKey().getAlgorithm(), PGPUtil.SHA1).setProvider("BC"));
        PGPPrivateKey pgpPrivKey = signKey.extractPrivateKey(
                new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .setProvider("BC").build(pass));
        sGen.init(PGPSignature.BINARY_DOCUMENT, pgpPrivKey);

        OutputStream cOut = comData.open(bOut);
        sGen.generateOnePassVersion(false).encode(cOut);

        PGPLiteralDataGenerator lGen = new PGPLiteralDataGenerator();
        OutputStream pOut = lGen.open(cOut, PGPLiteralData.BINARY, fileName, new File(fileName).length(), new Date());
        FileInputStream fIn = new FileInputStream(fileName);
        int ch;
        while ((ch = fIn.read()) >= 0) {
            pOut.write(ch);
            sGen.update((byte) ch);
        }
        fIn.close();
        lGen.close();
        sGen.generate().encode(cOut);
        comData.close();

        PGPEncryptedDataGenerator cPk = new PGPEncryptedDataGenerator(
                new JcePGPDataEncryptorBuilder(PGPEncryptedData.CAST5).setWithIntegrityPacket(withIntegrityCheck)
                        .setSecureRandom(new SecureRandom()).setProvider("BC"));

        cPk.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(encKey).setProvider("BC"));

        byte[] bytes = bOut.toByteArray();
        OutputStream encOut = cPk.open(out, bytes.length);
        encOut.write(bytes);
        encOut.close();
        out.close();
    }

    // Decrypt and verify data
    public static void decryptAndVerifyFile(InputStream in, OutputStream out,
                                            InputStream keyIn, char[] passwd, InputStream pubKeyIn)
            throws IOException, NoSuchProviderException {
        Security.addProvider(new BouncyCastleProvider());
        in = PGPUtil.getDecoderStream(in);

        try {
            PGPObjectFactory pgpF = new PGPObjectFactory(in, new JcaKeyFingerprintCalculator());
            PGPEncryptedDataList enc;
            Object o = pgpF.nextObject();

            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }

            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                    PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = findSecretKey(pgpSec, pbe.getKeyID(), passwd);
            }

            if (sKey == null) {
                throw new IllegalArgumentException("Secret key for message not found.");
            }

            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
            PGPObjectFactory plainFact = new PGPObjectFactory(clear, new JcaKeyFingerprintCalculator());
            PGPCompressedData cData = (PGPCompressedData) plainFact.nextObject();
            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream(), new JcaKeyFingerprintCalculator());
            PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();
            PGPOnePassSignature ops = p1.get(0);
            PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();
            InputStream dIn = p2.getInputStream();
            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
                    PGPUtil.getDecoderStream(pubKeyIn), new JcaKeyFingerprintCalculator());
            PGPPublicKey key = pgpRing.getPublicKey(ops.getKeyID());
            ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), key);
            int ch;
            while ((ch = dIn.read()) >= 0) {
                ops.update((byte) ch);
                out.write(ch);
            }
            out.close();

            PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();
            PGPSignature sig = p3.get(0);
            if (ops.verify(sig)) {
                System.out.println("signature verified.");
            } else {
                System.out.println("signature verification failed.");
            }
        } catch (PGPException e) {
            System.err.println(e);
            if (e.getUnderlyingException() != null) {
                e.getUnderlyingException().printStackTrace();
            }
        }
    }

    // Find secret key
    private static PGPPrivateKey findSecretKey(PGPSecretKeyRingCollection pgpSec, long keyID, char[] pass)
            throws PGPException {
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }

        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(new JcaPGPDigestCalculatorProviderBuilder().setProvider("BC").build()).setProvider("BC")
                .build(pass);

        return pgpSecKey.extractPrivateKey(decryptor);
    }

    // Read secret key
    public static PGPSecretKey readSecretKey(InputStream keyIn)
            throws IOException, PGPException {
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(
                PGPUtil.getDecoderStream(keyIn), new JcaKeyFingerprintCalculator());

        Iterator<PGPSecretKeyRing> keyRingIter = pgpSec.getKeyRings();
        while (keyRingIter.hasNext()) {
            PGPSecretKeyRing keyRing = keyRingIter.next();
            Iterator<PGPSecretKey> keyIter = keyRing.getSecretKeys();
            while (keyIter.hasNext()) {
                PGPSecretKey key = keyIter.next();
                if (key.isSigningKey()) {
                    return key;
                }
            }
        }

        throw new IllegalArgumentException("Can't find signing key in key ring.");
    }

    // Read public key
    public static PGPPublicKey readPublicKey(InputStream in) throws IOException, PGPException {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(PGPUtil.getDecoderStream(in), new JcaKeyFingerprintCalculator());

        Iterator<PGPPublicKeyRing> rIt = pgpPub.getKeyRings();
        while (rIt.hasNext()) {
            PGPPublicKeyRing kRing = rIt.next();
            Iterator<PGPPublicKey> kIt = kRing.getPublicKeys();
            while (kIt.hasNext()) {
                PGPPublicKey k = kIt.next();
                if (k.isEncryptionKey()) {
                    return k;
                }
            }
        }

        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

}