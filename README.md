# ContentTrust

Content trust component for the the G-Lens platform ([Gravitate Health](https://www.gravitatehealth.eu/)).
Used for providing data integrity for data shared within the platform.

## Building packages

Run `./gradlew build` to build the application jar, generated for each module in `<module-name>/build/libs/`,

Run `./gradlew bootBuildImage --imageName=content-trust/ct-app` to package the `ct-app` application as OCI container. 

## Requirements

* Java 17

## Configuration

Sample configuration is provided in `ct-app/conf/application.properties.sample`

For more information see [Spring Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.external-config.files)

## Running the application

* Jar `java -Dspring.config.location=/path/to/conf/application.properties -jar ct-app/build/libs/ct-app-*.jar`
* Docker `docker run -p 8080:8080 guardtime.com/content-trust/ct-app:<version>`

Environment variables can be passed:
  * As volume mount `-v /path/to/conf/:/workspace/config/`
  * Individually ` --env ksi.signer.url=... --env ksi.signer.userId=...`

## Running tests

To run integration tests locally, add following environment variables:
* `KSI_SIGNER_URL`, `KSI_SIGNER_USERID`, `KSI_SIGNER_SECRET`

## Static code analysis

### [Errorprone](https://errorprone.info)

Errorprone is a tool for Java that catches common programming mistakes at compile-time.
Any problems found will be reported as compilation errors.

### [SpotBugs](https://spotbugs.github.io/)

SpotBugs analyzes bytecode to find common bugs and code problems. This is done automatically when
running `./gradlew build`

XML and HTML reports can be found at `<module-name>/build/reports/spotbugs/`

### [OWASP Dependency-Check](https://owasp.org/www-project-dependency-check/)

Dependency-Check is a utility that identifies project dependencies and checks if there are any known, publicly
disclosed, vulnerabilities.

To run the analysis, use `./gradlew dependencyCheckAnalyze`

XML and HTML reports can be found at `<module-name>/build/reports/dependency-check/`
