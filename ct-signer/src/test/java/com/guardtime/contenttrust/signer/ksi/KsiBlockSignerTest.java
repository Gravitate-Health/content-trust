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
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizationException;
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizer;
import com.guardtime.ksi.SignatureReader;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.pdu.AggregationResponse;
import com.guardtime.ksi.service.Future;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.service.client.KSIClientException;
import com.guardtime.ksi.tlv.TLVElement;
import com.guardtime.ksi.unisignature.Identity;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class KsiBlockSignerTest {

    private static final String PREFERRED_USERNAME = "placeholder-client-id";
    private static KSISignature MOCK_SIGNATURE;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final KSISigningService ksiSigningService = mock(KSISigningService.class);
    private final KSISignatureFactory ksiSignatureFactory = mock(KSISignatureFactory.class);
    private final KsiBlockSigner ksiSigner = new KsiBlockSigner.Builder()
            .withKsiSigningService(ksiSigningService)
            .withKsiSignatureFactory(ksiSignatureFactory)
            .withMetadataMappings(Map.of("preferred_username", PREFERRED_USERNAME)).build();

    @BeforeAll
    static void setUp() throws KSIException {
        byte[] signatureBytes = getInputBytes("mock-signature-with-identity-metadata.ksig");
        MOCK_SIGNATURE = new SignatureReader().read(signatureBytes);
    }

    @Test
    void testSignResourceAndContainsIdentity() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        mockSignature();
        SigningResponse signingResponse = ksiSigner.sign(resource);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());

        KSISignature ksiSignature = new SignatureReader().read(signingResponse.signature());
        Identity[] identities = ksiSignature.getAggregationHashChainIdentity();
        Identity identity = identities[identities.length - 1];
        assertArrayEquals(PREFERRED_USERNAME.getBytes(StandardCharsets.UTF_8), identity.getClientId());
    }

    @Test
    void testSignResourceWithCanonicalizer() throws SigningCanonicalizationException, KSIException, IOException {
        SigningCanonicalizer canonicalizer = mock(SigningCanonicalizer.class);
        when(canonicalizer.processForSigning(any(byte[].class))).thenAnswer(i -> i.getArguments()[0]);
        KsiBlockSigner signerWithCanonicalizer = new KsiBlockSigner.Builder()
                .withKsiSigningService(ksiSigningService)
                .withKsiSignatureFactory(ksiSignatureFactory)
                .withMetadataMappings(Map.of("preferred_username", ""))
                .withCanonicalizer(canonicalizer).build();
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        mockSignature();
        SigningResponse signingResponse = signerWithCanonicalizer.sign(resource);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());
    }

    @Test
    void testSignResourceError() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("resource.json");
        JsonNode resource = objectMapper.readTree(inputBytes);
        when(ksiSigningService.sign(any(), any())).thenThrow(new KSIClientException("Error"));
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
        mockSignature();
        SigningResponse signingResponse = ksiSigner.sign(provenance);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());
    }

    @Test
    void testSignHash() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("hash.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        mockSignature();
        byte[] hash = Base64.getDecoder().decode(jsonNode.get("hash").asText());
        SigningResponse signingResponse = ksiSigner.sign(hash);
        assertEquals(SigningResponse.Status.OK, signingResponse.status());
    }

    @Test
    void testSignHashError() throws IOException, KSIException {
        byte[] inputBytes = getInputBytes("hash.json");
        JsonNode jsonNode = objectMapper.readTree(inputBytes);
        when(ksiSigningService.sign(any(), any())).thenThrow(new KSIClientException("Error"));
        byte[] hash = Base64.getDecoder().decode(jsonNode.get("hash").asText());
        SigningResponse signingResponse = ksiSigner.sign(hash);
        assertEquals(SigningResponse.Status.ERROR, signingResponse.status());
    }

    @Test
    void testExceptions() {
        SigningCanonicalizationException ex1 = new SigningCanonicalizationException("");
        SigningCanonicalizationException ex2 = new SigningCanonicalizationException("", new Throwable());
        assertEquals(ex1.getMessage(), ex2.getMessage());
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
