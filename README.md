# OCSP CRL Fallback Service

OCSP CRL Fallback Service is an OCSP server adapter for certificate revocation lists (CRLs). It acts like an OCSP server
and returns "good" OCSP responses for all certificates which are not in revocation lists and "revoked" responses for all
the certificates which are in the revocation lists.

## Prerequisites

* Java 17 JDK

## Building and Running Locally

Generate self-signed OCSP certificate and key:

* Run
  `docker run --rm -v "$(pwd):/work" -w /work alpine/openssl:3.5.4 req -batch -x509 -new -utf8 -text -not_before 20260106060000Z -not_after 20560106060000Z -noenc -newkey ec -pkeyopt ec_paramgen_curve:P-384 -keyout src/main/resources/ocsp-certificate/ocsp.key.pem -out src/main/resources/ocsp-certificate/ocsp.cer.pem -sha384 -subj '/CN=local-ocsp' -addext basicConstraints=CA:false -addext keyUsage=digitalSignature -addext extendedKeyUsage=OCSPSigning`

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

### Triggering a CRL reload

`POST /actuator/crlreload` downloads CRLs immediately instead of waiting for the next `crl-loading-interval` tick.
Not exposed by default - add `crlreload` to `management.endpoints.web.exposure.include`.

```shell
curl -k -X POST https://localhost:14443/actuator/crlreload \
     -H 'Content-Type: application/json' -H 'Accept: application/json' \
     -d '{"chain":"test_esteid2018"}'   # -d '{}' reloads all chains; unknown chain gives 404
```

The response holds one result per chain.

| Result | Meaning |
|--------|---------|
| `UPDATED` | The downloaded CRL was validated and is now in use. |
| `NOT_MODIFIED` | The distribution point answered 304 Not Modified, the previous CRL remains in use. |
| `REJECTED` | A CRL was downloaded but validation refused it. The previous CRL remains in use. |
| `BUSY` | A download for this chain was already running, so this request did nothing. |
| `FAILURE` | The download or the file handling threw; `error` holds the exception type only. |
| `UNKNOWN_CHAIN` | No chain with that name is configured. |

The HTTP status summarises the whole response:

| Status | When |
|--------|------|
| 200 | Every chain reported `UPDATED`, `NOT_MODIFIED` or `REJECTED`. |
| 404 | The requested chain name is not configured. |
| 409 | At least one chain reported `BUSY` and none reported `FAILURE`. |
| 500 | At least one chain reported `FAILURE`. |

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
