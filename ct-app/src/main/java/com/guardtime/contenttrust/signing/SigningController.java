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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.guardtime.contenttrust.canonicalizer.CanonicalizerImpl;
import com.guardtime.contenttrust.signer.Signer;
import com.guardtime.contenttrust.signer.SigningResponse;
import com.guardtime.contenttrust.signer.ksi.KsiBlockSigner;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class SigningController {

    private static final Logger logger = LoggerFactory.getLogger(SigningController.class);
    private static final String PROVENANCE_FIELD = "provenance";
    private static final String SIGNATURE_FIELD = "signature";
    private static final String PREFERRED_USERNAME = "preferred_username";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final KSISigningService ksiSigningService;
    private final KSISignatureFactory ksiSignatureFactory;

    public SigningController(KSISigningService ksiSigningService, KSISignatureFactory ksiSignatureFactory) {
        this.ksiSigningService = ksiSigningService;
        this.ksiSignatureFactory = ksiSignatureFactory;
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /**
     * Signs FHIR resource. If signProvenance is set to true, signs both resource and its provenance field.
     *
     * @param jsonResource   FHIR resource in JSON format.
     * @param signProvenance Boolean value that indicates whether to sign the nested provenance resource.
     * @return Provided FHIR resource in JSON format with signature added in "signature" field. Signature itself is
     *         encoded in Base64 format.
     */
    @PostMapping(path = "/sign/resource", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> signResource(
            @RequestBody JsonNode jsonResource,
            @RequestParam(required = false, defaultValue = "false") boolean signProvenance,
            Authentication authentication
    ) {
        Signer signer = initializeSigner(authentication);
        SigningResponse resourceSigningResponse = signer.sign(jsonResource);
        if (resourceSigningResponse.status() != SigningResponse.Status.OK) {
            byte[] errorMessageBytes = resourceSigningResponse.message().getBytes(StandardCharsets.UTF_8);
            return ResponseEntity.badRequest().body(errorMessageBytes);
        }
        ObjectNode returnedNode = (ObjectNode) jsonResource;
        SignatureWrapper signatureWrapper = wrapSignature(resourceSigningResponse.signature());
        returnedNode.putPOJO(SIGNATURE_FIELD, List.of(signatureWrapper));

        if (signProvenance) {
            logger.debug("Signing provenance resource.");
            JsonNode provenanceNodeToSign = jsonResource.get(PROVENANCE_FIELD);
            if (provenanceNodeToSign == null) {
                String errorMessage = "Resource did not contain provenance.";
                logger.debug(errorMessage);
                return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
            }
            // create new signer as it can't be reused
            signer = initializeSigner(authentication);
            SigningResponse provenanceSigningResponse = signer.sign(provenanceNodeToSign);
            if (provenanceSigningResponse.status() != SigningResponse.Status.OK) {
                byte[] errorMessageBytes = provenanceSigningResponse.message().getBytes(StandardCharsets.UTF_8);
                return ResponseEntity.badRequest().body(errorMessageBytes);
            }
            ObjectNode returnedProvenanceNode = (ObjectNode) provenanceNodeToSign;
            SignatureWrapper provenanceSignatureWrapper = wrapSignature(provenanceSigningResponse.signature());
            returnedProvenanceNode.putPOJO(SIGNATURE_FIELD, List.of(provenanceSignatureWrapper));
        }

        try {
            return ResponseEntity.ok().body(objectMapper.writeValueAsBytes(returnedNode));
        } catch (JsonProcessingException e) {
            String errorMessage = e.getMessage();
            logger.error(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Signs hash of FHIR resource.
     *
     * @param jsonNode Base64 encoded hash of FHIR resource in JSON format.
     * @return Provided hash node with signature added in "signature" field. Signature itself is
     *         encoded in Base64 format.
     */
    @PostMapping(path = "/sign/hash", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> signHash(
            @RequestBody JsonNode jsonNode,
            Authentication authentication
    ) {
        JsonNode hashNode = jsonNode.get("hash");
        if (hashNode == null) {
            String errorMessage = "Input did not contain hash.";
            logger.debug(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
        byte[] hash = Base64.getDecoder().decode(hashNode.asText());
        Signer signer = initializeSigner(authentication);
        SigningResponse hashSigningResponse = signer.sign(hash);
        if (hashSigningResponse.status() != SigningResponse.Status.OK) {
            byte[] errorMessageBytes = hashSigningResponse.message().getBytes(StandardCharsets.UTF_8);
            return ResponseEntity.badRequest().body(errorMessageBytes);
        }
        ObjectNode returnedNode = (ObjectNode) jsonNode;
        SignatureWrapper signatureWrapper = wrapSignature(hashSigningResponse.signature());
        returnedNode.putPOJO(SIGNATURE_FIELD, List.of(signatureWrapper));

        try {
            return ResponseEntity.ok().body(objectMapper.writeValueAsBytes(returnedNode));
        } catch (JsonProcessingException e) {
            String errorMessage = e.getMessage();
            logger.error(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
    }

    private Signer initializeSigner(Authentication authentication) {
        Map<String, String> metadataMappings = createMetadataMappings(authentication);
        return new KsiBlockSigner.Builder()
                .withKsiSigningService(ksiSigningService)
                .withKsiSignatureFactory(ksiSignatureFactory)
                .withMetadataMappings(metadataMappings)
                .withCanonicalizer(new CanonicalizerImpl())
                .build();
    }

    private Map<String, String> createMetadataMappings(Authentication authentication) {
        Jwt jwt = (Jwt) authentication.getPrincipal();
        String preferredUsername = jwt.getClaimAsString(PREFERRED_USERNAME);
        Map<String, String> metadataMappings = new LinkedHashMap<>();
        metadataMappings.put(PREFERRED_USERNAME, preferredUsername);
        return metadataMappings;
    }

    private SignatureWrapper wrapSignature(byte[] signature) {
        return new SignatureWrapper(Instant.now(), signature);
    }
}
