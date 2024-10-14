# ContentTrust

Content trust component for the the G-Lens platform ([Gravitate Health](https://www.gravitatehealth.eu/)).
Used for providing data integrity for data shared within the platform.

## Configuration

### Application properties

Sample configuration is provided in `application.properties.sample`. For more information supplying external configuration to Spring Boot application, consult [Spring Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.external-config.files).

### Configuring KeyCloak access (order is important)

0. (Optional) If KeyCloak realm name is not `master`, change it accordingly in import files.
1. Create client scope. 
   1. Content-trust is configured by default to verify scope by name `urn:gravitate-health:signing:sign`
   2. It can be configured by application property `keycloak.signing-scope`
2. Import `signer` role via `import-signer-role.json`.
3. Import `content-trust` client via `import-client`
   1. Optionally, `test-signer` user can be imported via same file, for testing purposes. That user already has `signer` role attached.
4. Add `signer` role to any users that require signing privileges. 

Access token created for any user with `signer` role should now have the configured client scope attached, used for verifying signing privilege.

## Running the application

Pull Docker image from Docker Hub - `docker pull martmagigt/content-trust:latest`

Run Docker container - `docker run martmagigt/content-trust`

Environment variables need to be passed in order to run the container above.

Mandatory:
* `--env ksi.signer.url=...`
* `--env ksi.signer.userId=...`
* `--env ksi.signer.secret=...` 
* `--env spring.security.oauth2.resourceserver.jwt.issuer-uri=...`

Optional: 
* `--env keycloak.signing-scope=...` to change default client scope value from `urn:gravitate-health:signing:sign`
* `--env server.port=...` to change exposed port of Java application
* ` -p 8080:8080` to change exposed port of Docker container

## REST endpoints

The application exposes two types of REST endpoints, signing and verifying.

Signing endpoints are authenticated and expect a KeyCloak token for authentication. 
The field `preferred_username` is extracted from the token and included in signature. 

Verification endpoints are unauthenticated.

### Signing and verifying FHIR resource

`POST /sign/resource?signProvenance=false`

Input is in JSON format and allows signing two types of FHIR resource:
1) FHIR resource or Provenance resource
2) FHIR resource with nested Provenance resource
   1. To sign both resources with one operation, set `signProvenance` query parameter to `true`.
   2. Otherwise, just the parent FHIR resource is signed.

Returns input JSON with Base64 encoded signature added in `signature.data` field.

`POST /verify/resource?verifyProvenance=false`

Input is in JSON format and allows verifying two types of FHIR resource:
1) FHIR resource or Provenance resource
2) FHIR resource with nested Provenance resource
   1. To verify signatures of both resources with one operation, set `verifyProvenance` query parameter to `true`.
   2. Otherwise, just the parent FHIR resource's signature is verified.

### Signing and verifying hash of FHIR resource

`POST /sign/hash`

Input is in JSON format, containing field `hash` - SHA256 hash of FHIR resource in Base64 encoding. 

The data must be in canonical form before hashing.

```json
{
  "hash": "Lby1U83uNNd7iPUxxOHpHfdcLRnLJZ/ryEe8xPuT1cw="
}
```

`POST /verify/hash`

Input is in JSON format, containing fields `hash` and `signature`, both in Base64 encoding.

```json
{
  "hash": "Lby1U83uNNd7iPUxxOHpHfdcLRnLJZ/ryEe8xPuT1cw=",
  "signature": "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"
}
```
