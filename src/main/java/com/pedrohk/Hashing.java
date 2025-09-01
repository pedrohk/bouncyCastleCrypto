package com.pedrohk;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;

public class Hashing {

    static {
        if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            java.security.Security.addProvider(new BouncyCastleProvider());
        }
    }

    public static String generateSha256(String data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256", BouncyCastleProvider.PROVIDER_NAME);
        byte[] hash = digest.digest(data.getBytes("UTF-8"));
        return new String(Hex.encode(hash));
    }
}

