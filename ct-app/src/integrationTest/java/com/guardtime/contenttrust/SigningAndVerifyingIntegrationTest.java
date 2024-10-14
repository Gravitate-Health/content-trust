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

package com.guardtime.contenttrust;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.util.Objects;

import static io.restassured.RestAssured.given;
import static jakarta.ws.rs.core.MediaType.APPLICATION_JSON;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Testcontainers // handles container lifecycle
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class SigningAndVerifyingIntegrationTest {

    @LocalServerPort
    private Integer port;

    private static final String SIGNING_ENDPOINT = "/sign/resource";
    private static final String VERIFICATION_ENDPOINT = "/verify/resource";
    private static final String REALM_IMPORT_FILENAME = "/test-import.json";
    // properties specified in realm import file
    private static final String REALM_NAME = "content-trust";
    private static final String CLIENT_ID = "content-trust";
    private static final String CLIENT_SECRET = "content-trust";
    private static final String USERNAME = "test-signer";
    private static final String PASSWORD = "test-signer";

    static {
        String keyCloakImageName = "quay.io/keycloak/keycloak:22.0.3";
        String keyCloakDockerImageName = DockerImageName.parse(keyCloakImageName).asCanonicalNameString();
        KEYCLOAK_CONTAINER = new KeycloakContainer(keyCloakDockerImageName)
                .withRealmImportFile(REALM_IMPORT_FILENAME);
    }

    @Container
    private static final KeycloakContainer KEYCLOAK_CONTAINER;

    @BeforeEach
    void setUp() {
        RestAssured.baseURI = "http://localhost:" + port;
    }

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        String issuerUri = KEYCLOAK_CONTAINER.getAuthServerUrl() + "/realms/" + REALM_NAME;
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri", () -> issuerUri);
        registry.add("ksi.signer.url", () -> System.getenv("KSI_SIGNER_URL"));
        registry.add("ksi.signer.userId", () -> System.getenv("KSI_SIGNER_USERID"));
        registry.add("ksi.signer.secret", () -> System.getenv("KSI_SIGNER_SECRET"));
    }

    @Test
    void testSigningAndVerifying() {
        byte[] resourceBytes = getInputBytes("resource.json");
        byte[] signedResourceBytes = given()
                .contentType(APPLICATION_JSON)
                .header("Authorization", getSignerBearerToken())
                .body(resourceBytes)
                .post(SIGNING_ENDPOINT).asByteArray();
        assertTrue(signedResourceBytes.length > 0);
        given()
                .contentType(APPLICATION_JSON)
                .body(signedResourceBytes)
                .post(VERIFICATION_ENDPOINT)
                .then().assertThat().statusCode(200)
                .body("resourceValidationResponse.status", equalTo("OK"));
    }

    @Test
    void testSigningAndVerifyingWithProvenance() {
        byte[] resourceBytes = getInputBytes("resource-with-provenance.json");
        byte[] signedResourceBytes = given()
                .contentType(APPLICATION_JSON)
                .queryParam("signProvenance", true)
                .header("Authorization", getSignerBearerToken())
                .body(resourceBytes)
                .post(SIGNING_ENDPOINT).asByteArray();
        assertTrue(signedResourceBytes.length > 0);
        given()
                .contentType(APPLICATION_JSON)
                .queryParam("verifyProvenance", true)
                .body(signedResourceBytes)
                .post(VERIFICATION_ENDPOINT)
                .then().assertThat().statusCode(200)
                .body("resourceValidationResponse.status", equalTo("OK"),
                        "provenanceValidationResponse.status", equalTo("OK"));
        given()
                .contentType(APPLICATION_JSON)
                .queryParam("verifyProvenance", false)
                .body(signedResourceBytes)
                .post(VERIFICATION_ENDPOINT)
                .then().assertThat().statusCode(200)
                .body("resourceValidationResponse.status", equalTo("OK"));
    }

    private String getSignerBearerToken() {
        try (Keycloak contentTrustClient = KeycloakBuilder.builder()
                .serverUrl(KEYCLOAK_CONTAINER.getAuthServerUrl())
                .realm(REALM_NAME)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
                .username(USERNAME)
                .password(PASSWORD)
                .build()) {
            String accessToken = contentTrustClient.tokenManager().getAccessToken().getToken();
            return String.format("Bearer %s", accessToken);
        }
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
