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
import com.guardtime.contenttrust.canonicalizer.CanonicalizerImpl;
import com.guardtime.contenttrust.verifier.VerificationResponse;
import com.guardtime.contenttrust.verifier.Verifier;
import com.guardtime.contenttrust.verifier.ksi.KsiVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class VerificationController {

    private static final Logger logger = LoggerFactory.getLogger(VerificationController.class);
    private static final String HASH_FIELD = "hash";
    private static final String PROVENANCE_FIELD = "provenance";
    private static final String SIGNATURE_FIELD = "signature";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final Verifier verifier;

    public VerificationController() {
        this.verifier = initializeVerifier();
    }

    /**
     * Verifies FHIR resource. If verifyProvenance is set to true, verifies both resource and its provenance field.
     *
     * @param jsonResource     FHIR resource in JSON format. Must contain JSON field "signature" in Base64 encoding.
     * @param verifyProvenance Boolean value that indicates whether to verify the nested provenance resource.
     * @return Byte array containing {@link VerificationResponse} domain object.
     */
    @PostMapping(path = "/verify/resource", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> verifyResource(
            @RequestBody JsonNode jsonResource,
            @RequestParam(required = false, defaultValue = "false") boolean verifyProvenance
    ) {
        JsonNode provenanceNodeToVerify = jsonResource.get(PROVENANCE_FIELD);
        VerificationResponseWrapper.Builder responseBuilder = new VerificationResponseWrapper.Builder();
        if (!verifyProvenance && provenanceNodeToVerify != null) {
            // edge case where provenance exists but user does not want to verify it
            ObjectNode objectNode = (ObjectNode) provenanceNodeToVerify;
            objectNode.remove(SIGNATURE_FIELD);
        }
        if (verifyProvenance) {
            logger.debug("Verifying provenance resource.");
            if (provenanceNodeToVerify == null) {
                String errorMessage = "Resource did not contain provenance.";
                logger.debug(errorMessage);
                return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
            }
            VerificationResponse provenanceVerificationResponse = verifier.verify(provenanceNodeToVerify);
            responseBuilder.withProvenanceValidationResponse(provenanceVerificationResponse);
        }

        VerificationResponse resourceVerificationResponse = verifier.verify(jsonResource);
        responseBuilder.withResourceValidationResponse(resourceVerificationResponse);

        try {
            return ResponseEntity.ok(objectMapper.writeValueAsBytes(responseBuilder.build()));
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            logger.error(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
    }

    /**
     * Verifies hash of FHIR resource.
     *
     * @param jsonNode JSON that must contain fields "hash" and "signature", both in Base64 encoding.
     * @return Byte array containing {@link VerificationResponse} domain object.
     */
    @PostMapping(path = "/verify/hash", consumes = APPLICATION_JSON_VALUE, produces = APPLICATION_JSON_VALUE)
    public ResponseEntity<byte[]> verifyHashAndSignature(
            @RequestBody JsonNode jsonNode
    ) {
        VerificationResponseWrapper.Builder responseBuilder = new VerificationResponseWrapper.Builder();
        JsonNode hashNode = jsonNode.get(HASH_FIELD);
        if (hashNode == null) {
            String errorMessage = "Input did not contain hash.";
            logger.debug(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
        JsonNode signatureNode = jsonNode.get(SIGNATURE_FIELD);
        if (signatureNode == null) {
            String errorMessage = "Input did not contain signature.";
            logger.debug(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
        byte[] hashBytes = Base64.getDecoder().decode(hashNode.asText());
        byte[] signatureBytes = Base64.getDecoder().decode(signatureNode.asText());
        VerificationResponse hashVerificationResponse = verifier.verify(hashBytes, signatureBytes);
        responseBuilder.withResourceValidationResponse(hashVerificationResponse);

        try {
            return ResponseEntity.ok(objectMapper.writeValueAsBytes(responseBuilder.build()));
        } catch (Exception e) {
            String errorMessage = e.getMessage();
            logger.error(errorMessage);
            return ResponseEntity.badRequest().body(errorMessage.getBytes(StandardCharsets.UTF_8));
        }
    }

    private Verifier initializeVerifier() {
        return new KsiVerifier.Builder()
                .withCanonicalizer(new CanonicalizerImpl())
                .build();
    }
}
