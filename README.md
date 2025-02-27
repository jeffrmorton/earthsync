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

### Instructions for Building and Running the Docker Container

#### Prerequisites

* **Docker**: Install Docker on your system (e.g., Docker Desktop for Windows/Mac, or Docker Engine for Linux).

* **Directory**: Ensure you're working in the earthsync-server/ directory containing package.json, .env, and the src/ folder.

#### Steps

1.  **Create the Dockerfile**:

  * Save the above content as Dockerfile (no extension) in the earthsync-server/ directory.

3.  **Build the Docker Image**:

  * Open a terminal and navigate to earthsync-server/.

  * Run the following command to build the Docker image:

    text

    WrapCopy

    `docker build -t earthsync-server:latest .`

  * Explanation:

    * -t earthsync-server:latest: Tags the image as earthsync-server with the latest version.

    * .: Specifies the current directory as the build context.

5.  **Run the Docker Container**:

  * Start the container with this command:

    text

    WrapCopy

    `docker run -d -p 3000:3000 --name earthsync-server earthsync-server:latest`

  * Explanation:

    * -d: Runs the container in detached mode (background).

    * -p 3000:3000: Maps port 3000 on the host to port 3000 in the container.

    * --name earthsync-server: Names the container for easy reference.

    * earthsync-server:latest: Specifies the image to run.

7.  **Verify the Container**:

  * Check that the container is running:

    text

    WrapCopy

    `docker ps`

  * You should see earthsync-server listed with status "Up".

  * Test the server by accessing http://localhost:3000 in a browser or via a tool like curl.

9.  **Environment Variables**:

  * If you need to override .env settings without modifying the file, pass them during the run command:

    text

    WrapCopy

    `docker run -d -p 3000:3000 --name earthsync-server -e "DATABASE_URL=your-db-url" -e "JWT_SECRET=your-secret" earthsync-server:latest`

  * Alternatively, update the .env file before building the image.

11. **Stop and Remove the Container (Optional)**:

  * Stop the running container:

    text

    WrapCopy

    `docker stop earthsync-server`

  * Remove the container:

    text

    WrapCopy

    `docker rm earthsync-server`

13. **Deploy to a Cloud Service (Optional)**:

  * **Docker Hub**:

    1. Tag the image:

      text

      WrapCopy

      `docker tag earthsync-server:latest yourusername/earthsync-server:latest`

    3. Push to Docker Hub (after logging in with docker login):

      text

      WrapCopy

      `docker push yourusername/earthsync-server:latest`

  * **AWS ECS**:

    1. Push the image to Amazon ECR (Elastic Container Registry).

    3. Create an ECS task definition and service, referencing the image.

    5. Configure networking (e.g., ALB for HTTPS).

* * *

### Notes

* **Dependencies**: The Dockerfile assumes all dependencies (e.g., PostgreSQL, Redis) are external services accessible via the network. Ensure these are running and their URLs are correctly set in .env.

* **SSL**: For production with WSS, you'll need to handle SSL outside the container (e.g., via a reverse proxy like Nginx) or modify the Dockerfile to include SSL certificates and update server.js to use HTTPS.

* **Volumes**: If you need persistent data (e.g., logs), add a volume mapping:

  text

  WrapCopy

  `docker run -d -p 3000:3000 -v /host/path:/app/logs earthsync-server:latest`

### Instructions for Using the Manifest File

#### Prerequisites

* **Kubernetes Cluster**: Ensure you have a running Kubernetes cluster (e.g., Minikube for local testing, or a cloud provider like AWS EKS, GKE).

* **kubectl**: Install the Kubernetes command-line tool (kubectl) on your system.

* **Docker Image**: Build and push the EarthSync server image to a container registry:

  bash

  WrapCopy

  `docker build -t yourusername/earthsync-server:latest . docker push yourusername/earthsync-server:latest`

#### Steps

1.  **Create the Manifest File**:

  * Save the content above as earthsync-server.yaml in a directory of your choice (e.g., earthsync-server/).

3.  **Customize the Manifest**:

  * Replace yourusername/earthsync-server:latest with your actual Docker image repository and tag.

  * Update the data section in the Secret with Base64-encoded values for your environment variables. To encode a value:

    bash

    WrapCopy

    `echo -n "your-value" | base64`\
    Example:

    bash

    WrapCopy

    `echo -n "postgres://user:password@postgres-host:5432/earthsync_db" | base64`\
    Replace the placeholder values in the Secret (data section) with the encoded outputs.

5.  **Apply the Manifest to Kubernetes**:

  * Open a terminal and navigate to the directory containing earthsync-server.yaml.

  * Apply the manifest:

    bash

    WrapCopy

    `kubectl apply -f earthsync-server.yaml`

  * This creates the Secret, Deployment, and Service in your cluster.

7.  **Verify Deployment**:

  * Check the pods:

    bash

    WrapCopy

    `kubectl get pods`

    * Look for a pod named something like earthsync-server-deployment-xxx with status "Running".

  * Check the service:

    bash

    WrapCopy

    `kubectl get svc`

    * You should see earthsync-server-service with a ClusterIP.

  * Check the secret:

    bash

    WrapCopy

    `kubectl get secret earthsync-server-secret`

9.  **Test Connectivity**:

  * For local testing with Minikube:

    bash

    WrapCopy

    `minikube service earthsync-server-service --url`

    * This provides a URL to access the service.

  * For a cluster environment, use kubectl port-forward to test locally:

    bash

    WrapCopy

    `kubectl port-forward deployment/earthsync-server-deployment 3000:3000`

    * Then access http://localhost:3000.

11. **Expose Externally (Optional)**:

  * Change spec.type from ClusterIP to LoadBalancer in the Service section and reapply:

    bash

    WrapCopy

    `kubectl apply -f earthsync-server.yaml`

  * Get the external IP:

    bash

    WrapCopy

    `kubectl get svc`

  * Alternatively, use an Ingress controller for more complex routing.

13. **Clean Up (Optional)**:

  * Delete the resources:

    bash

    WrapCopy

    `kubectl delete -f earthsync-server.yaml`

* * *

### Notes

* **External Dependencies**: The manifest assumes PostgreSQL and Redis are running separately (e.g., as other Kubernetes services or managed instances). Update the DATABASE_URL and REDIS_URL in the Secret with the correct connection strings.

* **Secrets**: The Secret stores sensitive data in Base64 format. For production, consider using a secrets management solution (e.g., HashiCorp Vault) or Kubernetes secrets from an external source instead of embedding them in the manifest.

* **Scaling**: Adjust replicas in the Deployment to scale the number of pods (e.g., replicas: 3).

* **Resources**: The resources section sets CPU/memory limits and requests. Modify these based on your cluster's capacity and application needs.

* **SSL**: For WebSocket Secure (WSS) in production, configure an Ingress with TLS or handle SSL termination outside Kubernetes (e.g., via a load balancer).

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