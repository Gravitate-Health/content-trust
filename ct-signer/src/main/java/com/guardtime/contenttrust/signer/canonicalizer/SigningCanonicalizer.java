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

package com.guardtime.contenttrust.signer.canonicalizer;

public interface SigningCanonicalizer {

    /**
     * Processes input byte array to its canonical form.
     *
     * @param data Input data as UTF-8 byte array.
     * @return Canonicalized data as UTF-8 byte array.
     * @throws SigningCanonicalizationException when parsing fails.
     */
    byte[] processForSigning(byte[] data) throws SigningCanonicalizationException;

    /**
     * Processes input string to its canonical form.
     *
     * @param data Input data as Base64 string.
     * @return Canonicalized data as Base64 string.
     * @throws SigningCanonicalizationException when parsing fails.
     */
    String processForSigning(String data) throws SigningCanonicalizationException;
}
