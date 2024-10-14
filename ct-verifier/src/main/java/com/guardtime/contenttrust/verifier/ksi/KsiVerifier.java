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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.guardtime.contenttrust.verifier.VerificationResponse;
import com.guardtime.contenttrust.verifier.Verifier;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizationException;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizer;
import com.guardtime.ksi.SignatureReader;
import com.guardtime.ksi.SignatureVerifier;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.verifier.VerificationResult;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicy;
import com.guardtime.ksi.unisignature.verifier.policies.ContextAwarePolicyAdapter;

import java.util.Base64;

public class KsiVerifier implements Verifier {

    private static final String SIGNATURE_FIELD = "signature";

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final SignatureVerifier verifier = new SignatureVerifier();
    private final ContextAwarePolicy contextAwarePolicy = ContextAwarePolicyAdapter.createInternalPolicy();
    private final VerificationCanonicalizer canonicalizer;

    private KsiVerifier(VerificationCanonicalizer canonicalizer) {
        this.canonicalizer = canonicalizer;
    }

    @Override
    public VerificationResponse verify(JsonNode jsonNode) {
        if (jsonNode == null) {
            return new VerificationResponse(VerificationResponse.Status.FAILED, "Input missing.");
        }
        ObjectNode objectNode = (ObjectNode) jsonNode;
        JsonNode signatureNode = objectNode.get(SIGNATURE_FIELD);
        if (signatureNode == null || signatureNode.isEmpty()) {
            return new VerificationResponse(VerificationResponse.Status.FAILED, "Signature missing.");
        }
        JsonNode signatureData = signatureNode.get(0).get("data");
        if (signatureData == null) {
            return new VerificationResponse(VerificationResponse.Status.FAILED, "Signature data missing.");
        }
        objectNode.remove(SIGNATURE_FIELD);

        try {
            SignatureReader signatureReader = new SignatureReader();
            byte[] signatureBytes = Base64.getDecoder().decode(signatureData.asText());
            KSISignature ksiSignature = signatureReader.read(signatureBytes);
            DataHasher dataHasher = new DataHasher(ksiSignature.getInputHash().getAlgorithm());
            byte[] bytesToVerify = objectMapper.writeValueAsBytes(objectNode);
            if (canonicalizer != null) {
                bytesToVerify = canonicalizer.processForVerification(bytesToVerify);
            }
            dataHasher.addData(bytesToVerify);
            VerificationResult verificationResult = verifier.verify(ksiSignature, dataHasher.getHash(), contextAwarePolicy);
            if (verificationResult.isOk()) {
                return new VerificationResponse();
            }
            return new VerificationResponse(VerificationResponse.Status.FAILED, verificationResult.getErrorCode().getMessage());
        } catch (KSIException | JsonProcessingException | VerificationCanonicalizationException e) {
            return new VerificationResponse(VerificationResponse.Status.FAILED, e.getMessage());
        }
    }

    @Override
    public VerificationResponse verify(byte[] hash, byte[] signature) {
        try {
            SignatureReader signatureReader = new SignatureReader();
            KSISignature ksiSignature = signatureReader.read(signature);
            DataHash dataHash = new DataHash(ksiSignature.getInputHash().getAlgorithm(), hash);
            VerificationResult verificationResult = verifier.verify(ksiSignature, dataHash, contextAwarePolicy);
            if (verificationResult.isOk()) {
                return new VerificationResponse();
            }
            return new VerificationResponse(VerificationResponse.Status.FAILED, verificationResult.getErrorCode().getMessage());
        } catch (KSIException e) {
            return new VerificationResponse(VerificationResponse.Status.ERROR, e.getMessage());
        }
    }

    public static class Builder {
        private VerificationCanonicalizer canonicalizer;

        public Builder withCanonicalizer(VerificationCanonicalizer canonicalizer) {
            this.canonicalizer = canonicalizer;
            return this;
        }

        public KsiVerifier build() {
            return new KsiVerifier(canonicalizer);
        }
    }
}
