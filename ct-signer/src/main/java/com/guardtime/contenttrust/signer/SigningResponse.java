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

package com.guardtime.contenttrust.signer;

/**
 * Domain object for signing response.
 *
 * @param status    Status of the signing process.
 * @param message   Message in case of any errors.
 * @param signature Byte array containing the signature in Base64 encoding.
 */
public record SigningResponse(
        Status status,
        String message,
        byte[] signature
) {
    public SigningResponse(byte[] signature) {
        this(Status.OK, null, signature);
    }

    public SigningResponse(Status status, String message) {
        this(status, message, null);
    }

    public enum Status {
        OK, FAILED, ERROR
    }
}
