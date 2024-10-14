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

package com.guardtime.contenttrust.canonicalizer;

import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizationException;
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizer;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizationException;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizer;
import org.erdtman.jcs.JsonCanonicalizer;

import java.io.IOException;

public class CanonicalizerImpl implements SigningCanonicalizer, VerificationCanonicalizer {
    @Override
    public byte[] processForSigning(byte[] data) throws SigningCanonicalizationException {
        try {
            return new JsonCanonicalizer(data).getEncodedUTF8();
        } catch (IOException e) {
            throw new SigningCanonicalizationException(e.getMessage(), e.getCause());
        }
    }

    @Override
    public String processForSigning(String data) throws SigningCanonicalizationException {
        try {
            return new JsonCanonicalizer(data).getEncodedString();
        } catch (IOException e) {
            throw new SigningCanonicalizationException(e.getMessage(), e.getCause());
        }
    }

    @Override
    public byte[] processForVerification(byte[] data) throws VerificationCanonicalizationException {
        try {
            return new JsonCanonicalizer(data).getEncodedUTF8();
        } catch (IOException e) {
            throw new VerificationCanonicalizationException(e.getMessage(), e.getCause());
        }
    }

    @Override
    public String processForVerification(String data) throws VerificationCanonicalizationException {
        try {
            return new JsonCanonicalizer(data).getEncodedString();
        } catch (IOException e) {
            throw new VerificationCanonicalizationException(e.getMessage(), e.getCause());
        }
    }
}
