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

package com.guardtime.contenttrust.signing;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.guardtime.ksi.SignatureReader;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SigningControllerTest {
    private static KSISignature MOCK_SIGNATURE;
    private static Authentication AUTHENTICATION;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final KSISigningService ksiSigningService = mock(KSISigningService.class);
    private final KSISignatureFactory ksiSignatureFactory = mock(KSISignatureFactory.class);
    private final SigningController signingController = new SigningController(ksiSigningService, ksiSignatureFactory);

    @BeforeAll
    static void setUp() throws KSIException {
        byte[] signatureBytes = getInputBytes("mock-signature.ksig");
        MOCK_SIGNATURE = new SignatureReader().read(signatureBytes);
        String bearerToken = new String(getInputBytes("bearer_token"), StandardCharsets.UTF_8);
        AUTHENTICATION = new JwtAuthenticationToken(Jwt.withTokenValue(bearerToken)
                .header("a", "b")
                .claim("preferred_username", "b").build());
    }

    @Test
    void signResource() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        mockSignature();
        ResponseEntity<byte[]> response = signingController.signResource(resource, false, AUTHENTICATION);
        assertTrue(response.getStatusCode().is2xxSuccessful());
        assertNotNull(objectMapper.readTree(response.getBody()).get("signature"));
    }

    @Test
    void signResourceWithProvenance() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource-with-provenance.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        mockSignature();
        ResponseEntity<byte[]> response = signingController.signResource(resource, true, AUTHENTICATION);
        assertTrue(response.getStatusCode().is2xxSuccessful());
        assertNotNull(objectMapper.readTree(response.getBody()).get("signature"));
        assertNotNull(objectMapper.readTree(response.getBody()).get("provenance").get("signature"));
    }

    @Test
    void signResourceWithoutProvenance() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        mockSignature();
        ResponseEntity<byte[]> response = signingController.signResource(resource, true, AUTHENTICATION);
        assertTrue(response.getStatusCode().is4xxClientError());
        assertArrayEquals("Resource did not contain provenance.".getBytes(StandardCharsets.UTF_8), response.getBody());
    }

    @Test
    void signResourceNull() {
        ResponseEntity<byte[]> response = signingController.signResource(null, true, AUTHENTICATION);
        assertTrue(response.getStatusCode().is4xxClientError());
        assertArrayEquals("Input missing.".getBytes(StandardCharsets.UTF_8), response.getBody());
    }

    @Test
    void signHash() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("hash.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        mockSignature();
        ResponseEntity<byte[]> response = signingController.signHash(jsonNode, AUTHENTICATION);
        assertTrue(response.getStatusCode().is2xxSuccessful());
        JsonNode responseNode = objectMapper.readTree(response.getBody());
        assertNotNull(responseNode.get("signature"));
    }

    @Test
    void signHashMissingHash() throws IOException {
        byte[] inputBytes = "{}".getBytes(StandardCharsets.UTF_8);
        JsonNode jsonHashNode = objectMapper.readTree(inputBytes);
        ResponseEntity<byte[]> response = signingController.signHash(jsonHashNode, AUTHENTICATION);
        assertTrue(response.getStatusCode().is4xxClientError());
        assertArrayEquals("Input did not contain hash.".getBytes(StandardCharsets.UTF_8), response.getBody());
    }

    @SuppressWarnings("unchecked")
    private void mockSignature() throws KSIException {
        AggregationResponse aggregationResponse = mock(AggregationResponse.class);
        when(aggregationResponse.getPayload()).thenReturn(TLVElement.create(2, new byte[] {0x01}));
        Future<AggregationResponse> future = mock(Future.class);
        when(future.getResult()).thenReturn(aggregationResponse);
        when(ksiSigningService.sign(any(), any())).thenReturn(future);
        when(ksiSignatureFactory.createSignature(any(), any(), any())).thenReturn(MOCK_SIGNATURE);
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
