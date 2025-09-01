package com.pedrohk;

import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;
import java.security.KeyPair;

public class DigitalSignatureTest {

    @Test
    void testSignAndVerify() throws Exception {
        KeyPair keyPair = KeyGeneration.generateAsymmetricKeysECDSA();
        String data = "My test need to be signed.";

        byte[] signature = DigitalSignature.sign(data, keyPair.getPrivate());
        boolean isVerified = DigitalSignature.verify(data, signature, keyPair.getPublic());

        assertTrue(isVerified);
    }
}