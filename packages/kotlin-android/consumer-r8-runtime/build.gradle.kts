// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

plugins {
    id("com.android.application")
}

android {
    namespace = "me.really.jose.consumer.r8"
    compileSdk = 37

    defaultConfig {
        applicationId = "me.really.jose.consumer.r8"
        minSdk = 24
        targetSdk = 37
        versionCode = 1
        versionName = "0.6.0"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_21
        targetCompatibility = JavaVersion.VERSION_21
    }

    sourceSets.getByName("main").assets.directories.add(
        file("../../../vectors").path,
    )

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = false
            signingConfig = signingConfigs.getByName("debug")
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "consumer-proguard-rules.pro",
            )
        }
    }
}

dependencies {
    if (providers.gradleProperty("reallyme.jose.androidConsumerRepository").isPresent) {
        implementation("me.really:jose-android:${rootProject.version}")
    } else {
        implementation(project(":"))
    }
}
