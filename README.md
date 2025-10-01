# OCSP CRL Fallback Service

OCSP CRL Fallback Service is an OCSP server adapter for certificate revocation lists (CRLs). It acts like an OCSP server
and returns "good" OCSP responses for all certificates which are not in revocation lists and "revoked" responses for all
the certificates which are in the revocation lists.

## Prerequisites

* Java 17 JDK

## Building and Running Locally

Edit the application.yml file as instructed by "Configuration" paragraph below.
Build and run the application:

```shell 
./mvnw spring-boot:run
```

## Building Docker image

1. Build
    * Either build locally
      ```shell
      ./mvnw spring-boot:build-image
      ```
    * Or build in Docker
      ```shell
      docker run --pull always --rm -u $(id -u):$(id -g) \
                 -v /var/run/docker.sock:/var/run/docker.sock \
                 -v "$HOME/.m2:/root/.m2" \
                 -v "$PWD:/usr/src/project" \
                 -w /usr/src/project \
                 maven:3.9-eclipse-temurin-17 \
                 mvn spring-boot:build-image
      ```
      Git Bash users on Windows should add `MSYS_NO_PATHCONV=1` in front of the command.

## Endpoints

* https://localhost:14443/ - OCSP service
* https://localhost:14443/actuator - maintenance endpoints

## Configuration

### TLS Certificate and Key

| Parameter        | Mandatory | Description, example |
| ---------------- | ---------- | ---------------- |
| `spring.ssl.bundle.pem.tls.keystore.certificate` | Yes | PEM-formatted TLS certificate used by application's HTTPS endpoints. Can be provided by path to file or by inlining it either directly into YAML or by using Base64. See [the Spring Boot documentation](https://docs.spring.io/spring-boot/reference/features/ssl.html#features.ssl.pem) for details. |
| `spring.ssl.bundle.pem.tls.keystore.private-key` | Yes | PEM-formatted TLS private key used by application's HTTPS endpoints. Can be provided by path to file or by inlining it either directly into YAML or by using Base64. See [the Spring Boot documentation](https://docs.spring.io/spring-boot/reference/features/ssl.html#features.ssl.pem) for details. |

## Non-pom.xml Licenses

* [Maven Wrapper](https://maven.apache.org/wrapper/) - Apache 2.0 license
