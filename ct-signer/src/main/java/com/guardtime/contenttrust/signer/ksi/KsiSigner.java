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
import com.guardtime.ksi.exceptions.KSIException;
import com.guardtime.ksi.hashing.DataHash;
import com.guardtime.ksi.hashing.DataHasher;
import com.guardtime.ksi.hashing.HashAlgorithm;
import com.guardtime.ksi.unisignature.KSISignature;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class KsiSigner implements Signer {

    private static final HashAlgorithm HASH_ALGORITHM = HashAlgorithm.SHA2_256;
    private final ObjectMapper objectMapper = new ObjectMapper();
    private final com.guardtime.ksi.Signer signer;

    public KsiSigner(com.guardtime.ksi.Signer signer) {
        this.signer = signer;
    }

    @Override
    public SigningResponse sign(JsonNode jsonNode) {
        if (jsonNode == null) {
            return new SigningResponse(SigningResponse.Status.FAILED, "Input missing.");
        }
        try {
            DataHasher dataHasher = new DataHasher(HASH_ALGORITHM);
            dataHasher.addData(objectMapper.writeValueAsBytes(jsonNode));
            DataHash dataHash = dataHasher.getHash();
            byte[] signatureBytes = createSignature(dataHash);
            return new SigningResponse(signatureBytes);
        } catch (KSIException | IOException e) {
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
        KSISignature signature = signer.sign(dataHash);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        signature.writeTo(baos);
        return baos.toByteArray();
    }
}
