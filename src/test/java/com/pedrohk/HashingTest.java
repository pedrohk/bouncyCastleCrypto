package com.pedrohk;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import org.junit.jupiter.api.Test;

public class HashingTest {

    @Test
    void testGenerateSha256() throws Exception {
        String data = "My test to be hashed.";
        String hash = Hashing.generateSha256(data);

        assertNotNull(hash);
        assertEquals(64, hash.length());

        String expectedHash = "7503da2239b1e5cc96b30213a80acb6658ed23b1ab9b451476124c908607f6b1";
        assertEquals(expectedHash, Hashing.generateSha256("My test to be hashed."));
    }
}