package com.tiger.common.secure;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyDataDecryptorFactoryBuilder;
import org.bouncycastle.util.io.Streams;

import java.io.*;
import java.security.Security;
import java.util.Iterator;

public class PgpDecryptUtil {

    public static void decrypt(InputStream instream, InputStream privateKeyInStream,
                               String password, OutputStream outputStream) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        instream = PGPUtil.getDecoderStream(instream);

        try {
            JcaPGPObjectFactory pgpF = new JcaPGPObjectFactory(instream);
            PGPEncryptedDataList enc;
            Object o = pgpF.nextObject();
            // the first object might be a PGP marker packet.
            if (o instanceof PGPEncryptedDataList) {
                enc = (PGPEncryptedDataList) o;
            } else {
                enc = (PGPEncryptedDataList) pgpF.nextObject();
            }
            Iterator<PGPEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPrivateKey sKey = null;
            PGPPublicKeyEncryptedData pbe = null;
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(privateKeyInStream),
                    new JcaKeyFingerprintCalculator());
            while (sKey == null && it.hasNext()) {
                pbe = (PGPPublicKeyEncryptedData) it.next();
                sKey = PGPCoreUtil.findSecretKey(pgpSec, pbe.getKeyIdentifier().getKeyId(), password.toCharArray());
            }
            if (sKey == null) {
                throw new IllegalArgumentException("secret key for message not found.");
            }
            InputStream clear = pbe.getDataStream(new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC")
                    .build(sKey));
            JcaPGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            if (message instanceof PGPCompressedData) {
                JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(((PGPCompressedData) message).getDataStream());
                message = pgpFact.nextObject();
            }
            if (message instanceof PGPLiteralData) {
                InputStream unc = ((PGPLiteralData) message).getInputStream();
                Streams.pipeAll(unc, outputStream);
            } else if (message instanceof PGPOnePassSignatureList) {
                throw new PGPException("encrypted message contains a signed message - not literal data.");
            } else {
                throw new PGPException("message is not a simple encrypted file - type unknown.");
            }
            if (pbe.isIntegrityProtected() && pbe.verify()) {
                System.out.println("message integrity check passed");
            } else {
                System.out.println("message integrity check failed");
            }
        } catch (PGPException e) {
            System.out.println(e.getMessage());
            // TODO: throw PGPException
        } finally {
            privateKeyInStream.close();
            instream.close();
        }
    }

    public static void decryptFile(String encryptedInputFileName, String privateKeyFileName, char[] passPhrase,
                                   String defaultFileName) throws IOException {
        InputStream mainstream = new BufferedInputStream(new FileInputStream(encryptedInputFileName));
        InputStream privateKeyInStream = new BufferedInputStream(new FileInputStream(privateKeyFileName));
        OutputStream fOut = new FileOutputStream(defaultFileName);
        decrypt(mainstream, privateKeyInStream, new String(passPhrase), fOut);
        fOut.close();
    }
}
