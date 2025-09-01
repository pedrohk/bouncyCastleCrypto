package com.pedrohk;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;
import javax.crypto.SecretKey;

public class SymmetricEncryptionTest {

    @Test
    void testEncryptDecrypt() throws Exception {
        SecretKey key = KeyGeneration.generateSymmetricKey();
        String originalText = "This is my secret message for symmetric encryption.";

        byte[] encrypted = SymmetricEncryption.encrypt(originalText, key);
        String decrypted = SymmetricEncryption.decrypt(encrypted, key);

        assertEquals(originalText, decrypted);
    }
}