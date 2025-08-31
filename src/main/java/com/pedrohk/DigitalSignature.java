package com.pedrohk;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class DigitalSignature {

    private static final String ALGORITHM = "SHA256withECDSA";

    static {
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static byte[] sign(String data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(data.getBytes());
        return signature.sign();
    }

    public static boolean verify(String data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(publicKey);
        signature.update(data.getBytes());
        return signature.verify(signatureBytes);
    }
}
