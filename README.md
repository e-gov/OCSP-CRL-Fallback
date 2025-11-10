# OCSP CRL Fallback Service

OCSP CRL Fallback Service is an OCSP server adapter for certificate revocation lists (CRLs). It acts like an OCSP server
and returns "good" OCSP responses for all certificates which are not in revocation lists and "revoked" responses for all
the certificates which are in the revocation lists.

## Prerequisites

* Java 17 JDK

## Building and Running Locally

Generate self-signed OCSP certificate and key:

```shell
local/generate-ocsp-signing-certificate.sh
```

Edit `src/main/resources/application.yml` file as instructed by "Configuration" paragraph below.
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
| `spring.ssl.bundle.pem.ocsp.keystore.certificate` | Yes | PEM-formatted OCSP certificate. Can be provided by path to file or by inlining it either directly into YAML or by using Base64. See [the Spring Boot documentation](https://docs.spring.io/spring-boot/reference/features/ssl.html#features.ssl.pem) for details. |
| `spring.ssl.bundle.pem.ocsp.keystore.private-key` | Yes | PEM-formatted TLS private key used by application's HTTPS endpoints. Can be provided by path to file or by inlining it either directly into YAML or by using Base64. See [the Spring Boot documentation](https://docs.spring.io/spring-boot/reference/features/ssl.html#features.ssl.pem) for details. |

### Loading CRLs

| Parameter        | Mandatory | Description, example |
| ---------------- | ---------- | ---------------- |
| `ocsp-crl-fallback.crl-loading-interval` | No | Interval for downloading updated CRL-s from remote sources. Default value is 30 seconds. [See the exact format from JavaDoc.](https://docs.spring.io/spring-framework/docs/current/javadoc-api/org/springframework/scheduling/annotation/Scheduled.html#fixedDelayString%28%29) Example: 60s |
| `ocsp-crl-fallback.certificate-chains` | No | List of CRLs to download |
| `ocsp-crl-fallback.certificate-chains[].name` | Yes | Name for the certificate chain. The downloaded CRL files will be named `<certificate-chain-name>.crl` |
| `ocsp-crl-fallback.certificate-chains[].issuer-certificate` | Yes | Issuer certificate for the particular certificate chain |
| `ocsp-crl-fallback.certificate-chains[].crl-download` | Yes | Data needed to download a specific CRL |
| `ocsp-crl-fallback.certificate-chains[].crl-download.url` | Yes | URL to download the CRL from |
| `ocsp-crl-fallback.certificate-chains[].crl-download.timeout` | Yes | Timeout for downloading the CRL. 30s by default. [See allowed formats here.](https://docs.spring.io/spring-boot/4.0/reference/features/external-config.html#features.external-config.typesafe-configuration-properties.conversion.durations) |
| `ocsp-crl-fallback.certificate-chains[].crl-download.tls-truststore-bundle` | No | TLS truststore bundle with the HTTPS certificate for CRL download URL. This parameter refers to the bundles defined under `spring.ssl.bundle.pem.*` setting. It is not used for HTTP URLs. If this parameter is undefined and an HTTPS URL is specified for downloading the CRL, the default Java truststore is used instead. |
| `ocsp-crl-fallback.tmp-path` | Yes | Temporary directory to download CRLs into. Example: /var/cache/ocspcrl/tmp |

## Non-pom.xml Licenses

* [Maven Wrapper](https://maven.apache.org/wrapper/) - Apache 2.0 license
