package com.pedrohk;

import javax.crypto.Cipher;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AsymmetricEncryption {

    private static final String ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

    static {
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static byte[] encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(plainText.getBytes());
    }

    public static String decrypt(byte[] cipherText, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM, BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedText = cipher.doFinal(cipherText);
        return new String(decryptedText);
    }
}

