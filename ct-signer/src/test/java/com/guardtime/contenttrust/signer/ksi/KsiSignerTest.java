/*
 * GUARDTIME CONFIDENTIAL
 *
 * Copyright 2008-2023 Guardtime, Inc.
 * All Rights Reserved.
 *
 * All information contained herein is, and remains, the property
 * of Guardtime, Inc. and its suppliers, if any.
 * The intellectual and technical concepts contained herein are
 * proprietary to Guardtime, Inc. and its suppliers and may be
 * covered by U.S. and foreign patents and patents in process,
 * and/or are protected by trade secret or copyright law.
 * Dissemination of this information or reproduction of this material
 * is strictly forbidden unless prior written permission is obtained
 * from Guardtime, Inc.
 * "Guardtime" and "KSI" are trademarks or registered trademarks of
 * Guardtime, Inc., and no license to trademarks is granted; Guardtime
 * reserves and retains all trademark rights.
 */

package com.guardtime.contenttrust.signer.ksi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.guardtime.contenttrust.signer.SigningResponse;
import com.guardtime.ksi.SignatureReader;
import com.guardtime.ksi.Signer;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.KSISignature;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Base64;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KsiSignerTest {
    private static KSISignature MOCK_SIGNATURE;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Signer signer = mock(Signer.class);
    private final KsiSigner ksiSigner = new KsiSigner(signer);

    @BeforeAll
    static void setUp() throws KSIException {
        byte[] signatureBytes = getInputBytes("mock-signature.ksig");
        MOCK_SIGNATURE = new SignatureReader().read(signatureBytes);
    }

    @Test
    void testSignResource() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        byte[] resourceBytes = objectMapper.writeValueAsBytes(resource);
        when(signer.sign(new DataHasher().addData(resourceBytes).getHash())).thenReturn(MOCK_SIGNATURE);
        SigningResponse signingResponse = ksiSigner.sign(resource);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());
    }

    @Test
    void testSignResourceError() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        byte[] resourceBytes = objectMapper.writeValueAsBytes(resource);
        when(signer.sign(new DataHasher().addData(resourceBytes).getHash())).thenThrow(new KSIException(""));
        SigningResponse signingResponse = ksiSigner.sign(resource);
        assertEquals(SigningResponse.Status.ERROR, signingResponse.status());
    }

    @Test
    void testSignNull() {
        JsonNode resource = null;
        SigningResponse signingResponse = ksiSigner.sign(resource);
        assertEquals(SigningResponse.Status.FAILED, signingResponse.status());
        assertEquals("Input missing.", signingResponse.message());
    }

    @Test
    void testSignProvenance() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("provenance.json");
        JsonNode provenance = objectMapper.readTree(inputBytes);
        byte[] provenanceBytes = objectMapper.writeValueAsBytes(provenance);
        when(signer.sign(new DataHasher().addData(provenanceBytes).getHash())).thenReturn(MOCK_SIGNATURE);
        SigningResponse signingResponse = ksiSigner.sign(provenance);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());
    }

    @Test
    void testSignHash() throws KSIException, IOException {
        byte[] inputBytes = getInputBytes("hash.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        byte[] hash = Base64.getDecoder().decode(jsonNode.get("hash").asText());
        when(signer.sign(new DataHash(HashAlgorithm.SHA2_256, hash))).thenReturn(MOCK_SIGNATURE);
        SigningResponse signingResponse = ksiSigner.sign(hash);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());
    }

    private static byte[] getInputBytes(String fileName) {
        try {
            ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            return Objects.requireNonNull(contextClassLoader.getResourceAsStream(fileName)).readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
