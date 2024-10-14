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

package com.guardtime.contenttrust.verification;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VerificationControllerTest {

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final VerificationController verificationController = new VerificationController();

    @Test
    void verifyResource() throws IOException {
        byte[] inputBytes = getInputBytes("resource-with-base64-ksi-signature.json");
        JsonNode resourceNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyResource(resourceNode, false);
        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    void verifyResourceWithProvenance() throws IOException {
        byte[] inputBytes = getInputBytes("resource-with-provenance-base64-ksi-signatures.json");
        JsonNode resourceNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyResource(resourceNode, true);
        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    void verifyResourceWithoutVerifyingProvenance() throws IOException {
        byte[] inputBytes = getInputBytes("resource-with-provenance-base64-ksi-signatures.json");
        JsonNode resourceNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyResource(resourceNode, false);
        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    void verifyResourceWithoutSignature() throws IOException {
        byte[] inputBytes = getInputBytes("resource-with-provenance.json");
        JsonNode resourceNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyResource(resourceNode, false);
        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    void verifyResourceWithoutProvenance() throws IOException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resourceNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyResource(resourceNode, true);
        assertTrue(response.getStatusCode().is4xxClientError());
        assertArrayEquals("Resource did not contain provenance.".getBytes(StandardCharsets.UTF_8), response.getBody());
    }

    @Test
    void verifyHashAndSignature() throws IOException {
        byte[] inputBytes = getInputBytes("hash-with-base64-ksi-signature.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyHashAndSignature(jsonNode);
        assertTrue(response.getStatusCode().is2xxSuccessful());
    }

    @Test
    void verifyHashAndSignatureMissingHash() throws IOException {
        byte[] inputBytes = getInputBytes("hash-with-base64-ksi-signature.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        ObjectNode objectNode = (ObjectNode) jsonNode;
        objectNode.remove("hash");
        ResponseEntity<byte[]> response = verificationController.verifyHashAndSignature(objectNode);
        assertTrue(response.getStatusCode().is4xxClientError());
        assertArrayEquals("Input did not contain hash.".getBytes(StandardCharsets.UTF_8), response.getBody());
    }

    @Test
    void verifyHashAndSignatureMissingSignature() throws IOException {
        byte[] inputBytes = getInputBytes("hash.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = verificationController.verifyHashAndSignature(jsonNode);
        assertTrue(response.getStatusCode().is4xxClientError());
        assertArrayEquals("Input did not contain signature.".getBytes(StandardCharsets.UTF_8), response.getBody());
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
