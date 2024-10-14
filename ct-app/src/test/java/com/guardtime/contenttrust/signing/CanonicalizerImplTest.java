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

import com.guardtime.contenttrust.canonicalizer.CanonicalizerImpl;
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizationException;
import com.guardtime.contenttrust.signer.canonicalizer.SigningCanonicalizer;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizationException;
import com.guardtime.contenttrust.verifier.canonicalizer.VerificationCanonicalizer;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

// Test data from https://cyberphone.github.io/doc/security/browser-json-canonicalization.html
class CanonicalizerImplTest {

    private static final SigningCanonicalizer signingCanonicalizer = new CanonicalizerImpl();
    private static final VerificationCanonicalizer verificationCanonicalizer = new CanonicalizerImpl();

    @Test
    void processArrays() throws SigningCanonicalizationException {
        String actual = signingCanonicalizer.processForSigning("""
                [
                  56,
                  {
                    "d": true,
                    "10": null,
                    "1": [ ]
                  }
                ]""");
        String expected = """
                [56,{"1":[],"10":null,"d":true}]""";
        assertEquals(expected, actual);
    }

    @Test
    void processFrench() throws SigningCanonicalizationException {
        String actual = signingCanonicalizer.processForSigning("""
                {
                  "peach": "This sorting order",
                  "péché": "is wrong according to French",
                  "pêche": "but canonicalization MUST",
                  "sin":   "ignore locale"
                }""");
        String expected = """
                {"peach":"This sorting order","péché":"is wrong according to French","pêche":"but canonicalization MUST"\
                ,"sin":"ignore locale"}""";
        assertEquals(expected, actual);
    }

    @Test
    void processStructures() throws SigningCanonicalizationException {
        String actual = signingCanonicalizer.processForSigning("""
                {
                   "1": {"f": {"f": "hi","F": 5} ,"\\n": 56.0},
                   "10": { },
                   "": "empty",
                   "a": { },
                   "111": [ {"e": "yes","E": "no" } ],
                   "A": { }
                 }""");
        String expected = """
                {"":"empty","1":{"\\n":56,"f":{"F":5,"f":"hi"}},"10":{},"111":[{"E":"no","e":"yes"}],"A":{},"a":{}}""";
        assertEquals(expected, actual);
    }

    @Test
    void processUnicode() throws SigningCanonicalizationException {
        String actual = signingCanonicalizer.processForSigning("""
                {
                  "Unnormalized Unicode":"A\\u030a"
                }""");
        String expected = """
                {"Unnormalized Unicode":"Å"}""";
        assertEquals(expected, actual);
    }

    @Test
    void processFhirResource() throws SigningCanonicalizationException, VerificationCanonicalizationException {
        byte[] inputBytes = getInputBytes("json-edge-cases.json");
        byte[] expectedBytes = getInputBytes("json-edge-cases-canonical.json");
        String inputString = new String(inputBytes, StandardCharsets.UTF_8);
        String expectedString = new String(expectedBytes, StandardCharsets.UTF_8);
        String actualSigning = signingCanonicalizer.processForSigning(inputString);
        String actualVerification1 = verificationCanonicalizer.processForVerification(actualSigning);
        String actualVerification2 = verificationCanonicalizer.processForVerification(inputString);
        assertEquals(expectedString, actualSigning);
        assertEquals(expectedString, actualVerification1);
        assertEquals(expectedString, actualVerification2);
    }

    @Test
    void processExceptions() {
        byte[] inputBytes = new byte[] {};
        String inputString = "";
        assertThrows(SigningCanonicalizationException.class, () -> signingCanonicalizer.processForSigning(inputBytes));
        assertThrows(SigningCanonicalizationException.class, () -> signingCanonicalizer.processForSigning(inputString));
        assertThrows(VerificationCanonicalizationException.class, () ->
                verificationCanonicalizer.processForVerification(inputBytes));
        assertThrows(VerificationCanonicalizationException.class, () ->
                verificationCanonicalizer.processForVerification(inputString));
    }

    private static byte[] getInputBytes(String fileName) {
        try {
            ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
            return Objects.requireNonNull(contextClassLoader.getResourceAsStream(fileName)).readAllBytes();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}


