import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
  kotlin("jvm") version "1.9.24"
  `maven-publish`
  signing
}

group = providers.gradleProperty("GROUP").orNull ?: "com.ideascale.commons"
version = providers.gradleProperty("VERSION").orNull ?: "0.1.0-SNAPSHOT"

kotlin {
  jvmToolchain(17)
}

java {
  withSourcesJar()
  withJavadocJar()
}

repositories {
  mavenCentral()
  mavenLocal()
}

tasks.withType<KotlinCompile>().configureEach {
  kotlinOptions {
    jvmTarget = "17"
    freeCompilerArgs += listOf("-Xjsr305=strict")
  }
}

publishing {
  publications {
    create<MavenPublication>("maven") {
      from(components["java"])
      artifactId = "commons-security"

      pom {
        name.set("ideascale-commons-security")
        description.set("Dead-simple policy-based authorization library (v1).")
        url.set("https://example.invalid/ideascale-commons-security")

        licenses {
          license {
            name.set("Apache-2.0")
            url.set("https://www.apache.org/licenses/LICENSE-2.0")
          }
        }

        developers {
          developer {
            id.set("ideascale")
            name.set("IdeaScale")
          }
        }

        scm {
          connection.set("scm:git:https://example.invalid/ideascale-commons-security.git")
          developerConnection.set("scm:git:https://example.invalid/ideascale-commons-security.git")
          url.set("https://example.invalid/ideascale-commons-security")
        }
      }
    }
  }

  repositories {
    mavenLocal()

    // Optional remote publishing:
    // ./gradlew publish -PpublishUrl=https://... -PpublishUser=... -PpublishPassword=...
    val publishUrl = providers.gradleProperty("publishUrl").orNull
    if (!publishUrl.isNullOrBlank()) {
      maven {
        name = "remote"
        url = uri(publishUrl)
        credentials {
          username = providers.gradleProperty("publishUser").orNull
          password = providers.gradleProperty("publishPassword").orNull
        }
      }
    }
  }
}

// Optional signing (only active if you provide signing properties).
signing {
  // To enable: set signing.keyId, signing.password, signing.secretKeyRingFile or use in-memory keys
  // See Gradle Signing Plugin docs.
  sign(publishing.publications["maven"])
  isRequired = providers.gradleProperty("signingRequired").map { it.toBoolean() }.orElse(false).get()
}
