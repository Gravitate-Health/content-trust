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

package com.guardtime.contenttrust.verifier;

import com.fasterxml.jackson.databind.JsonNode;

public interface Verifier {

    /**
     * Verifies signature of provided FHIR resource. Excludes signature from verification, if present in {@link JsonNode}.
     *
     * @param jsonNode {@link JsonNode} object containing FHIR resource.
     * @return {@link VerificationResponse} object.
     */
    VerificationResponse verify(JsonNode jsonNode);

    /**
     * Verifies signature of provided hash.
     *
     * @param hash      byte array containing hash of the FHIR resource.
     * @param signature byte array containing signature.
     * @return {@link VerificationResponse} object.
     */
    VerificationResponse verify(byte[] hash, byte[] signature);
}
