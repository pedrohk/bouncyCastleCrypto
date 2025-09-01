package com.pedrohk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import java.security.KeyPair;

public class AsymmetricEncryptionTest {

    @Test
    void testEncryptDecrypt() throws Exception {
        KeyPair keyPair = KeyGeneration.generateAsymmetricKeysRSA();
        String originalText = "This is my secret message for asymmetric encryption.";

        byte[] encrypted = AsymmetricEncryption.encrypt(originalText, keyPair.getPublic());
        String decrypted = AsymmetricEncryption.decrypt(encrypted, keyPair.getPrivate());

        assertEquals(originalText, decrypted);
    }
}
