plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.sniveil.app"
    // compileSdk/targetSdk 35 = Android 15, the latest stable release at
    // the time this was written. Bump both here when a newer API ships.
    compileSdk = 35

    defaultConfig {
        applicationId = "com.sniveil.app"
        minSdk = 24
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"
    }

    // --- 16 KB page size compatibility (required for Android 15+ devices
    // that ship with a 16KB memory page size) ---
    // This app has no native (.so) libraries, so there is nothing to
    // re-align — but these settings are kept so that if a native
    // dependency (e.g. a future libwireguard.so) is added later, AGP
    // packages it uncompressed and 16KB-aligned automatically.
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
    buildFeatures {
        viewBinding = true
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
}
