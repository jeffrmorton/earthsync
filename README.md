EarthSync Deployment Instructions
=================================

Overview
--------

**EarthSync** is a brainwave entrainment app that synchronizes users with Earth's natural frequencies, enhanced with Bluetooth integration for entrainment devices like heart rate monitors and visual tools. This README provides instructions for deploying both the server-side (Node.js) and client-side (Flutter) components.

* * * * *

Server Deployment
-----------------

### Prerequisites

-   **Node.js**: Install version 16+ with npm (Node Package Manager).

-   **PostgreSQL**: Set up locally or use a managed service (e.g., AWS RDS).

-   **Redis**: Install locally or use a managed service (e.g., Redis Cloud).

-   **Firebase**: Configure for notifications by creating a project and downloading serviceAccount.json.

### Setup Directory

1.  Create a folder named earthsync-server.

3.  Inside earthsync-server, create a src subfolder.

5.  Place the following files:

    -   src/db.js

    -   src/middleware.js

    -   src/server.js

    -   .env (root level)

    -   package.json (root level)

### Installation

1.  Open a terminal and navigate to earthsync-server.

3.  Run the following command to install dependencies:

    `npm install`

5.  Configure the .env file with your credentials:

    `DATABASE_URL=postgres://user:password@host:5432/earthsync_db JWT_SECRET=your-secure-secret-key\
    PORT=3000\
    FIREBASE_SERVICE_ACCOUNT=/path/to/serviceAccount.json\
    REDIS_URL=redis://:your-redis-password@your-redis-host:6379\
    SENTRY_DSN=https://your-sentry-dsn@sentry.io/your-project-id\
    API_KEY_SECRET=your-api-key-secret`

### Database Initialization

-   Ensure PostgreSQL is running and accessible via the DATABASE_URL.

-   The initDb function in db.js automatically creates tables and a test user (test, password123) on startup.

### Run Server

-   For production, run:

    `npm start`

-   For development (with auto-restart via nodemon), run:

    `npm run dev`

-   Verify the server is accessible at http://localhost:3000 (or your specified PORT).

### SSL Configuration

-   For WebSocket Secure (WSS), secure the connection:

    -   Obtain an SSL certificate (e.g., via Let's Encrypt).

    -   Modify the server to use HTTPS (replace app.listen with https.createServer) or set up a reverse proxy (e.g., Nginx) with SSL.

### Deploy to Cloud

-   **Heroku**:

    1.  Initialize a Heroku app:

        `heroku create`

    3.  Push the code:

        `git push heroku main`

    5.  Set environment variables:

        `heroku config:set DATABASE_URL=your-db-url JWT_SECRET=your-secret ...`

-   **AWS EC2**:

    1.  Copy the earthsync-server folder to an EC2 instance.

    3.  Install Node.js and dependencies (npm install).

    5.  Use a process manager like PM2:

        `pm2 start src/server.js`

* * * * *

Client Deployment
-----------------

### Prerequisites

-   **Flutter**: Install version 3+ with Dart.

-   **Development Environment**: Set up an Android/iOS emulator or connect a physical device.

-   **Firebase**: Configure the app with Firebase (add google-services.json for Android, GoogleService-Info.plist for iOS).

### Setup Directory

1.  Create a folder named earthsync.

3.  Create the following subfolders:

    -   android/app/src/main/kotlin/com/example/earthsync

    -   ios/Runner

    -   lib/l10n

    -   assets

5.  Place files as follows:

    -   android/app/src/main/kotlin/com/example/earthsync/BinauralPlugin.kt

    -   ios/Runner/BinauralPlugin.swift

    -   lib/l10n/app_en.arb, lib/l10n/app_es.arb

    -   lib/main.dart, lib/resonance_graph.dart, lib/resonance_globe.dart, lib/settings.dart, lib/audio.dart

    -   assets/earth.obj, assets/earth.png, assets/splash_earth.png, assets/meditation_5min.mp3, assets/rain.mp3, assets/forest.mp3

    -   pubspec.yaml (root level)

### Installation

1.  Open a terminal and navigate to earthsync.

3.  Install dependencies:

    `flutter pub get`

5.  Add assets to the assets/ folder:

    -   If real assets are unavailable, create placeholder files (e.g., touch earth.obj) or source from:

        -   3D models: [Free3D](https://free3d.com/)

        -   Audio: [Freesound](https://freesound.org/)

### Native Configuration

-   **Android**:

    -   Update android/app/src/main/AndroidManifest.xml for background audio and Bluetooth:

        `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.earthsync">\
        <uses-permission android:name="android.permission.BLUETOOTH"/>\
        <uses-permission android:name="android.permission.BLUETOOTH_ADMIN"/>\
        <application\
        android:label="EarthSync"\
        android:icon="@mipmap/ic_launcher">\
        <service android:name="com.ryanheise.audioservice.AudioService"/>\
        </application>\
        </manifest>`

-   **iOS**:

    -   Update ios/Runner/Info.plist for background audio and Bluetooth:

        `<key>UIBackgroundModes</key> <array>\
        <string>audio</string>\
        </array>\
        <key>NSBluetoothAlwaysUsageDescription</key>\
        <string>EarthSync needs Bluetooth to connect to entrainment devices.</string>`

### Run App

-   Test the app on an emulator or device:

    `flutter run`

-   Replace https://your-server.com in the code with your actual server URL.

### Build for Release

-   **Android**:

    `flutter build apk --release`

-   **iOS**:

    `flutter build ios --release`

    -   Open ios/Runner.xcworkspace in Xcode, archive, and submit to the App Store.

### Deploy to Stores

-   **Google Play**:

    -   Upload the generated APK to the Google Play Console.

-   **App Store**:

    -   Use Xcode to submit the iOS build to App Store Connect.

-   **App Description**: Include a note about device integration:

    `Connect to heart rate monitors or visual entrainment devices via Bluetooth for a personalized experience.`

### Testing Device Integration

1.  Ensure Bluetooth is enabled on the test device.

3.  Test with a heart rate monitor (e.g., Polar H10) or simulate a visual entrainment device using a Bluetooth development kit (e.g., Arduino with BLE).

5.  Verify:

    -   Frequency updates are sent to the connected device (check DeviceIntegrationManager.sendFrequency).

    -   Feedback data (e.g., heart rate) is received and affects app behavior (e.g., preset adjustments).

* * * * *

Deployment Notes
----------------

-   **Assets**: The assets listed (earth.obj, earth.png, etc.) are placeholders. Replace them with actual files from sources like Free3D or Freesound.

-   **Server URL**: Update all instances of https://your-server.com in the code with your deployed server's domain or IP address.

-   **Bluetooth Permissions**: The app requests Bluetooth permissions automatically via flutter_blue, but confirm functionality on both iOS and Android.

-   **Custom Devices**: For visual entrainment devices with custom UUIDs, replace custom_service_id and frequency_control_char in DeviceIntegrationScreen with actual values from the device's documentation.

* * * * *

Save this content as README.md in your project root directory (e.g., earthsync/ or earthsync-server/). Let me know if you need additional sections (e.g., project overview, contribution guidelines) or further assistance!