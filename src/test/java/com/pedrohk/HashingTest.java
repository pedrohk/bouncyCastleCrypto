package com.pedrohk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

public class HashingTest {

    @Test
    void testGenerateSha256() throws Exception {
        String data = "This is the data to be hashed.";
        String hash = Hashing.generateSha256(data);

        assertNotNull(hash);
        assertEquals(64, hash.length());

        String expectedHash = "1adb557517668f2634c85649901434af87cef3625e3a2fd9f80638c719f76114";
        assertEquals(expectedHash, Hashing.generateSha256("This is the data to be hashed."));
    }
}