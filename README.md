# ideascale-commons-security (Gradle project)

This is a minimal Gradle (Kotlin DSL) project that builds and publishes the authorization library as a Maven artifact.

## Requirements
- JDK 17+
- Gradle installed OR generate a wrapper:
  - `gradle wrapper --gradle-version 8.7`

## Build
- `gradle clean build`

## Publish to Maven Local
- `gradle publishToMavenLocal`

## Publish to a remote Maven repo (optional)
Provide properties:
- `publishUrl`
- `publishUser`
- `publishPassword`

Example:
- `gradle publish -PpublishUrl=https://maven.example.com/repository/releases -PpublishUser=USER -PpublishPassword=PASS`

## Coordinates
By default:
- groupId: from `GROUP` (gradle.properties)
- artifactId: `commons-security`
- version: from `VERSION` (gradle.properties)

Change `GROUP`/`VERSION` in `gradle.properties` or pass `-PGROUP=... -PVERSION=...`.
