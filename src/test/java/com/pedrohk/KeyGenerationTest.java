package com.pedrohk;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import java.security.KeyPair;
import javax.crypto.SecretKey;

public class KeyGenerationTest {

    @Test
    void testGenerateSymmetricKey() throws Exception {
        SecretKey secretKey = KeyGeneration.generateSymmetricKey();
        assertNotNull(secretKey);
        assertEquals("AES", secretKey.getAlgorithm());
        assertEquals(32, secretKey.getEncoded().length); // 256 bits
    }

    @Test
    void testGenerateAsymmetricKeysRSA() throws Exception {
        KeyPair keyPair = KeyGeneration.generateAsymmetricKeysRSA();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("RSA", keyPair.getPublic().getAlgorithm());
    }

    @Test
    void testGenerateAsymmetricKeysECDSA() throws Exception {
        KeyPair keyPair = KeyGeneration.generateAsymmetricKeysECDSA();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPublic());
        assertNotNull(keyPair.getPrivate());
        assertEquals("ECDSA", keyPair.getPublic().getAlgorithm());
    }
}
