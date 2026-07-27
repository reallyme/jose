// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

plugins {
    id("com.android.application")
}

android {
    namespace = "me.really.jose.consumer.r8"
    compileSdk = 36

    defaultConfig {
        applicationId = "me.really.jose.consumer.r8"
        minSdk = 24
        targetSdk = 36
        versionCode = 1
        versionName = "0.3.0"
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
    implementation(project(":"))
}
