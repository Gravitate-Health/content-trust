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

package com.guardtime.contenttrust.verifier.ksi;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.guardtime.contenttrust.verifier.VerificationResponse;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizationException;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.Base64;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KsiVerifierTest {

    private static final VerificationCanonicalizer canonicalizer = mock(VerificationCanonicalizer.class);
    private final KsiVerifier ksiVerifier = new KsiVerifier.Builder()
            .withCanonicalizer(canonicalizer).build();
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeAll
    static void setUp() throws VerificationCanonicalizationException {
        when(canonicalizer.processForVerification(any(byte[].class))).thenAnswer(i -> i.getArguments()[0]);
    }

    @Test
    void testVerifyResource() throws IOException {
        byte[] inputBytes = getInputBytes("resource-with-base64-ksi-signature.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        VerificationResponse verificationResponse = ksiVerifier.verify(resource);
        assertEquals(VerificationResponse.Status.OK, verificationResponse.status());
    }

    @Test
    void testVerifyResourceModifiedFile() throws IOException {
        byte[] inputBytes = getInputBytes("resource-with-base64-ksi-signature.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        ObjectNode modifiedResource = (ObjectNode) resource;
        modifiedResource.put("resourceType", "modified-resource-type");
        VerificationResponse verificationResponse = ksiVerifier.verify(resource);
        assertEquals(VerificationResponse.Status.FAILED, verificationResponse.status());
        assertEquals("Wrong document", verificationResponse.message());
    }

    @Test
    void testVerifyResourceInputMissing() {
        VerificationResponse verificationResponse = ksiVerifier.verify(null);
        assertEquals(VerificationResponse.Status.FAILED, verificationResponse.status());
        assertEquals("Input missing.", verificationResponse.message());
    }

    @Test
    void testVerifyProvenance() throws IOException {
        byte[] inputBytes = getInputBytes("provenance-with-base64-ksi-signature.json");
        JsonNode provenance = objectMapper.readTree(inputBytes);
        VerificationResponse verificationResponse = ksiVerifier.verify(provenance);
        assertEquals(VerificationResponse.Status.OK, verificationResponse.status());
    }

    @Test
    void testVerifyHashWithSignature() throws IOException {
        byte[] inputBytes = getInputBytes("hash-with-base64-ksi-signature.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        byte[] hash = Base64.getDecoder().decode(jsonNode.get("hash").asText());
        byte[] ksiSignatureBytes = Base64.getDecoder().decode(jsonNode.get("signature").asText());
        VerificationResponse verificationResponse = ksiVerifier.verify(hash, ksiSignatureBytes);
        assertEquals(VerificationResponse.Status.OK, verificationResponse.status());
    }

    @Test
    void testVerifyModifiedHash() throws IOException {
        byte[] inputBytes = getInputBytes("hash-with-base64-ksi-signature.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        byte[] hash = Base64.getDecoder().decode(jsonNode.get("hash").asText());
        byte[] ksiSignatureBytes = Base64.getDecoder().decode(jsonNode.get("signature").asText());
        hash[1] = 0x30;
        VerificationResponse verificationResponse = ksiVerifier.verify(hash, ksiSignatureBytes);
        assertEquals(VerificationResponse.Status.FAILED, verificationResponse.status());
        assertEquals("Wrong document", verificationResponse.message());
    }

    @Test
    void testExceptions() {
        VerificationCanonicalizationException ex1 = new VerificationCanonicalizationException("");
        VerificationCanonicalizationException ex2 = new VerificationCanonicalizationException("", new Throwable());
        assertEquals(ex1.getMessage(), ex2.getMessage());
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
