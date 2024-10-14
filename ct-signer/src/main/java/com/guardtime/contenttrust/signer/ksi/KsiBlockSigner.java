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
import com.guardtime.contenttrust.signer.Signer;
import com.guardtime.contenttrust.signer.SigningResponse;
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizationException;
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizer;
import com.guardtime.ksi.blocksigner.IdentityMetadata;
import com.guardtime.ksi.blocksigner.KsiBlockSignerBuilder;
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.service.KSISigningService;
import com.guardtime.ksi.tree.HashTreeBuilder;
import com.guardtime.ksi.unisignature.KSISignature;
import com.guardtime.ksi.unisignature.KSISignatureFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.List;
import java.util.Map;

public class KsiBlockSigner implements Signer {

    private static final Logger logger = LoggerFactory.getLogger(KsiBlockSigner.class);
    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA2_256;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final com.guardtime.ksi.blocksigner.KsiBlockSigner signer;
    private final Map<String, String> metadataMappings;
    private final SigningCanonicalizer canonicalizer;

    private KsiBlockSigner(
            KSISigningService ksiSigningService,
            KSISignatureFactory ksiSignatureFactory,
            Map<String, String> metadataMappings,
            SigningCanonicalizer canonicalizer
    ) {
        this.signer = initializeSigner(ksiSigningService, ksiSignatureFactory);
        this.metadataMappings = metadataMappings;
        this.canonicalizer = canonicalizer;
    }

    @Override
    public SigningResponse sign(JsonNode jsonNode) {
        if (jsonNode == null) {
            return new SigningResponse(SigningResponse.Status.FAILED, "Input missing.");
        }
        try {
            byte[] bytesToSign = objectMapper.writeValueAsBytes(jsonNode);
            if (canonicalizer != null) {
                bytesToSign = canonicalizer.processForSigning(bytesToSign);
            }
            DataHasher dataHasher = new DataHasher(HASH_ALGORITHM);
            dataHasher.addData(bytesToSign);
            DataHash dataHash = dataHasher.getHash();
            byte[] signatureBytes = createSignature(dataHash);
            return new SigningResponse(signatureBytes);
        } catch (KSIException | IOException | SigningCanonicalizationException e) {
            return new SigningResponse(SigningResponse.Status.ERROR, e.getMessage());
        }
    }

    @Override
    public SigningResponse sign(byte[] hash) {
        try {
            DataHash dataHash = new DataHash(HASH_ALGORITHM, hash);
            byte[] signatureBytes = createSignature(dataHash);
            return new SigningResponse(signatureBytes);
        } catch (KSIException e) {
            return new SigningResponse(SigningResponse.Status.ERROR, e.getMessage());
        }
    }

    private byte[] createSignature(DataHash dataHash) throws KSIException {
        for (Map.Entry<String, String> entry : metadataMappings.entrySet()) {
            String clientId = entry.getKey();
            String machineId = entry.getValue();
            if (clientId == null) {
                logger.warn("Map key was null");
                continue;
            }
            if (machineId == null) {
                logger.warn("Value for signature metadata element {} was null", clientId);
            }
            signer.add(dataHash, new IdentityMetadata(clientId, machineId, null, null));
        }
        List<KSISignature> ksiSignatures = signer.sign();
        if (ksiSignatures.size() != 1) {
            logger.debug("Expected to receive exactly 1 KSI signature from block signer, received {}", ksiSignatures.size());
        }
        KSISignature signature = ksiSignatures.get(0);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        signature.writeTo(baos);
        return baos.toByteArray();
    }

    private com.guardtime.ksi.blocksigner.KsiBlockSigner initializeSigner(
            KSISigningService ksiSigningService,
            KSISignatureFactory ksiSignatureFactory
    ) {
        return new KsiBlockSignerBuilder()
                .setKsiSigningService(ksiSigningService)
                .setSignatureFactory(ksiSignatureFactory)
                .setTreeBuilder(new HashTreeBuilder(HASH_ALGORITHM))
                .build();
    }

    public static class Builder {
        private KSISigningService ksiSigningService;
        private KSISignatureFactory ksiSignatureFactory;
        private Map<String, String> metadataMappings;
        private SigningCanonicalizer canonicalizer;

        public Builder withKsiSigningService(KSISigningService ksiSigningService) {
            this.ksiSigningService = ksiSigningService;
            return this;
        }

        public Builder withKsiSignatureFactory(KSISignatureFactory ksiSignatureFactory) {
            this.ksiSignatureFactory = ksiSignatureFactory;
            return this;
        }

        public Builder withMetadataMappings(Map<String, String> metadataMappings) {
            this.metadataMappings = metadataMappings;
            return this;
        }

        public Builder withCanonicalizer(SigningCanonicalizer canonicalizer) {
            this.canonicalizer = canonicalizer;
            return this;
        }

        public KsiBlockSigner build() {
            return new KsiBlockSigner(ksiSigningService, ksiSignatureFactory, metadataMappings, canonicalizer);
        }
    }
}
