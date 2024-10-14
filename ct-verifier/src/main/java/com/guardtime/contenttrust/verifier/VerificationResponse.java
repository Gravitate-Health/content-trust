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

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Domain object for verification response.
 *
 * @param status  Status of the verification process.
 * @param message Message in case of any errors.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerificationResponse(
        Status status,
        String message
) {

    public VerificationResponse() {
        this(Status.OK, null);
    }

    public enum Status {
        OK, FAILED, ERROR
    }
}
