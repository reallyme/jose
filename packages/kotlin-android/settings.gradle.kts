// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        providers.gradleProperty("reallyme.jose.androidConsumerRepository").orNull?.let { directory ->
            exclusiveContent {
                forRepository { maven { url = uri(directory) } }
                filter { includeModule("me.really", "jose-android") }
            }
        }
        google { content { excludeModule("me.really", "jose-android") } }
        mavenCentral { content { excludeModule("me.really", "jose-android") } }
    }
}

rootProject.name = "reallyme-jose-android"

include(":consumer-r8-runtime")
