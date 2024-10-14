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

import java.time.Instant;
import java.util.List;

public record SignatureWrapper(
        List<Coding> type,
        Instant when,
        String who,
        String onBehalfOf,
        String targetFormat,
        String sigFormat,
        byte[] data
) {
    public SignatureWrapper(Instant when, byte[] data) {
        this(List.of(new Coding()), when, null, null, null,
                "https://guardtime.github.io/ksi-java-sdk/com/guardtime/ksi/unisignature/KSISignature.html", data);
    }

    public record Coding(
            String system,
            String version,
            String code,
            String display,
            boolean userSelected
    ) {
        public Coding() {
            this("Content-Trust", "1.0", "KSI", "KSI Signature", false);
        }
    }
}
