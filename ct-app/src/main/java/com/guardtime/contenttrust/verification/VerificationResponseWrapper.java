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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.guardtime.contenttrust.verifier.VerificationResponse;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record VerificationResponseWrapper(
        VerificationResponse resourceValidationResponse,
        VerificationResponse provenanceValidationResponse
) {
    private VerificationResponseWrapper(Builder builder) {
        this(
                builder.resourceValidationResponse,
                builder.provenanceValidationResponse
        );
    }

    public static class Builder {
        private VerificationResponse resourceValidationResponse;
        private VerificationResponse provenanceValidationResponse;

        public Builder withResourceValidationResponse(VerificationResponse resourceValidationResponse) {
            this.resourceValidationResponse = resourceValidationResponse;
            return this;
        }

        public Builder withProvenanceValidationResponse(VerificationResponse provenanceValidationResponse) {
            this.provenanceValidationResponse = provenanceValidationResponse;
            return this;
        }

        public VerificationResponseWrapper build() {
            return new VerificationResponseWrapper(this);
        }
    }
}
