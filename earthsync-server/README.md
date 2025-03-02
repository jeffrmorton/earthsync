# EarthSync Server

EarthSync is a Node.js-based server designed to deliver real-time Schumann frequency updates through WebSocket connections and provide RESTful API endpoints for user management, frequency logging, and usage tracking. It leverages PostgreSQL for persistent data storage and Redis for efficient WebSocket message broadcasting.

## Features
- **User Management**: Secure registration and JWT-based authentication.
- **API Key System**: Generate and use API keys for frequency updates.
- **Real-Time Updates**: Encrypted Schumann frequency broadcasts via WebSocket.
- **Usage Tracking**: Log user activity and retrieve statistics.
- **Deployment Flexibility**: Supports standalone Docker containers or Kubernetes clusters.

## Prerequisites
- **Docker**: Required for containerized deployment (tested with Docker 20.10+).
- **Node.js**: Needed for local testing and script execution (v18.19.1 recommended).
- **npm**: Dependency management (bundled with Node.js).
- **curl**: For API testing (install with `sudo apt install curl` on Linux/WSL).
- **Kubernetes** (optional): For Kubernetes deployment (e.g., Minikube, kind, or a managed cluster like GKE/AKS/EKS).
- **kubectl** (optional): For managing Kubernetes resources (install with `sudo apt install kubectl`).
- **Operating System**: Instructions assume a Unix-like environment (Linux/WSL/macOS); adjust for Windows CMD if necessary.

## Project Structure

earthsync-server/├── src/│ ├── db.js # Database schema initialization and operations│ ├── middleware.js # JWT authentication middleware│ ├── server.js # Core server logic│ ├── test-websocket.js # WebSocket testing script├── Dockerfile # Docker image configuration├── package.json # Node.js dependencies and scripts├── .env # Environment variables (example provided)├── test-earthsync-server.sh # Automated test script└── README.md # Project documentation

textWrapCopy## Setup (Docker)### 1. Clone the RepositoryIf starting from a Git repository:\`\`\`bashgit clone cd earthsync-server

### 2\. Install Dependencies

Install Node.js dependencies required for building the Docker image:

bashWrapCopynpm install

### 3\. Configure Environment Variables

Create a .env file in the project root:

bashWrapCopynano .env

Add and customize:

textWrapCopyDATABASE\_URL=postgres://earthsync\_user:your\_secure\_password@postgres:5432/earthsync\_dbJWT\_SECRET=your-secure-secret-keyPORT=3000REDIS\_URL=redis://:your\_secure\_redis\_password@redis:6379API\_KEY\_SECRET=your-api-key-secret

*   Replace your\_secure\_password and your\_secure\_redis\_password with strong, unique passwords.

*   Use postgres and redis as aliases for Docker --link or Kubernetes service names.

### 4\. Build the Server Docker Image

bashWrapCopydocker build -t earthsync-server:latest .

Running the Server (Docker)

---------------------------

### 1\. Start PostgreSQL Container

bashWrapCopydocker run -d \\ --name earthsync-postgres \\ -e POSTGRES\_USER=earthsync\_user \\ -e POSTGRES\_PASSWORD=your\_secure\_password \\ -e POSTGRES\_DB=earthsync\_db \\ -p 5432:5432 \\ -v earthsync\_data:/var/lib/postgresql/data \\ postgres:14

### 2\. Start Redis Container

bashWrapCopydocker run -d \\ --name earthsync-redis \\ -e REDIS\_PASSWORD=your\_secure\_redis\_password \\ -p 6379:6379 \\ -v earthsync\_redis\_data:/data \\ redis:7 redis-server --requirepass your\_secure\_redis\_password

### 3\. Start Server Container

bashWrapCopydocker run -d \\ --name earthsync-server \\ -p 3000:3000 \\ --link earthsync-redis:redis \\ --link earthsync-postgres:postgres \\ earthsync-server:latest

### 4\. Verify Containers

Check that all containers are running:

bashWrapCopydocker ps

*   Expected: earthsync-postgres, earthsync-redis, and earthsync-server listed with "Up" status.

### 5\. Review Logs

bashWrapCopydocker logs earthsync-server

*   Confirm successful startup:textWrapCopyInitializing database schema...Users table created or already existsFrequency\_history table created or already existsUsage\_logs table created or already existsApi\_keys table created or already existsTest user inserted or already existsDatabase schema initialized successfullyConnected to PostgreSQLRedis connections initialized successfullyServer running on port 3000

Running the Server (Kubernetes)

-------------------------------

### 1\. Create Kubernetes Manifest

Create a file named earthsync-k8s.yaml:

bashWrapCopynano earthsync-k8s.yaml

Add the following manifest:

yamlWrapCopyapiVersion: v1kind: Secretmetadata: name: earthsync-secretstype: Opaquedata: postgres-password: eW91ci1zZWN1cmUtcGFzc3dvcmQ= _\# base64: your\_secure\_password_ redis-password: eW91ci1zZWN1cmUtcmVkaXMtcGFzc3dvcmQ= _\# base64: your\_secure\_redis\_password_ jwt-secret: eW91ci1zZWN1cmUtc2VjcmV0LWtleQ== _\# base64: your-secure-secret-key_ api-key-secret: eW91ci1hcGktc2VjcmV0 _\# base64: your-api-key-secret_\---apiVersion: v1kind: PersistentVolumeClaimmetadata: name: postgres-pvcspec: accessModes: - ReadWriteOnce resources: requests: storage: 1Gi---apiVersion: v1kind: PersistentVolumeClaimmetadata: name: redis-pvcspec: accessModes: - ReadWriteOnce resources: requests: storage: 1Gi---apiVersion: apps/v1kind: Deploymentmetadata: name: postgresspec: replicas: 1 selector: matchLabels: app: postgres template: metadata: labels: app: postgres spec: containers: - name: postgres image: postgres:14 env: - name: POSTGRES\_USER value: earthsync\_user - name: POSTGRES\_PASSWORD valueFrom: secretKeyRef: name: earthsync-secrets key: postgres-password - name: POSTGRES\_DB value: earthsync\_db ports: - containerPort: 5432 volumeMounts: - name: postgres-storage mountPath: /var/lib/postgresql/data volumes: - name: postgres-storage persistentVolumeClaim: claimName: postgres-pvc---apiVersion: v1kind: Servicemetadata: name: postgresspec: ports: - port: 5432 targetPort: 5432 selector: app: postgres---apiVersion: apps/v1kind: Deploymentmetadata: name: redisspec: replicas: 1 selector: matchLabels: app: redis template: metadata: labels: app: redis spec: containers: - name: redis image: redis:7 command: \["redis-server", "--requirepass", "$(REDIS\_PASSWORD)"\] env: - name: REDIS\_PASSWORD valueFrom: secretKeyRef: name: earthsync-secrets key: redis-password ports: - containerPort: 6379 volumeMounts: - name: redis-storage mountPath: /data volumes: - name: redis-storage persistentVolumeClaim: claimName: redis-pvc---apiVersion: v1kind: Servicemetadata: name: redisspec: ports: - port: 6379 targetPort: 6379 selector: app: redis---apiVersion: apps/v1kind: Deploymentmetadata: name: earthsync-serverspec: replicas: 1 selector: matchLabels: app: earthsync-server template: metadata: labels: app: earthsync-server spec: containers: - name: earthsync-server image: earthsync-server:latest env: - name: DATABASE\_URL value: postgres://earthsync\_user:$(POSTGRES\_PASSWORD)@postgres:5432/earthsync\_db - name: REDIS\_URL value: redis://:$(REDIS\_PASSWORD)@redis:6379 - name: JWT\_SECRET valueFrom: secretKeyRef: name: earthsync-secrets key: jwt-secret - name: API\_KEY\_SECRET valueFrom: secretKeyRef: name: earthsync-secrets key: api-key-secret - name: PORT value: "3000" - name: POSTGRES\_PASSWORD valueFrom: secretKeyRef: name: earthsync-secrets key: postgres-password - name: REDIS\_PASSWORD valueFrom: secretKeyRef: name: earthsync-secrets key: redis-password ports: - containerPort: 3000---apiVersion: v1kind: Servicemetadata: name: earthsync-serverspec: type: LoadBalancer _\# Use NodePort or ClusterIP for local clusters_ ports: - port: 3000 targetPort: 3000 selector: app: earthsync-server

*   **Notes**:

    *   Replace base64 values in the Secret with your own (e.g., echo -n "your\_secure\_password" | base64).

    *   PVCs provide 1Gi storage; adjust as needed.

    *   LoadBalancer exposes externally; use NodePort for local testing (e.g., Minikube).

### 2\. Apply the Manifest

*   Start a Kubernetes cluster (e.g., Minikube):bashWrapCopyminikube start

*   Apply the manifest:bashWrapCopykubectl apply -f earthsync-k8s.yaml

*   Verify pods:bashWrapCopykubectl get pods

    *   Expect postgres, redis, and earthsync-server pods in "Running" state.

### 3\. Access the Server

*   Get the service URL (Minikube):bashWrapCopyminikube service earthsync-server --url

    *   Adjust SERVER\_URL and WS\_URL in test-earthsync-server.sh if not localhost:3000.

*   Or port-forward locally:bashWrapCopykubectl port-forward svc/earthsync-server 3000:3000

### 4\. Check Logs

bashWrapCopykubectl logs -l app=earthsync-server

*   Confirm schema initialization and connections as in Docker logs.

Testing

-------

### Run the Test Script

The script validates all server functionality:

bashWrapCopychmod +x test-earthsync-server.shsudo ./test-earthsync-server.sh

*   Successful output confirms endpoint and WebSocket functionality.

*   Note: Manually ensure containers (Docker) or pods (Kubernetes) are running, as the script doesn't check status.

### Manual Testing (Optional)

*   **Login**:bashWrapCopycurl -X POST http://localhost:3000/login -H "Content-Type: application/json" -d '{"username":"test","password":"password123"}'

*   **WebSocket**: Use the JWT from login:bashWrapCopynode src/test-websocket.js ""

Troubleshooting

---------------

*   **Schema Errors**: If tables (e.g., frequency\_history) are missing, review logs for initDb issues:

    *   **Docker**:bashWrapCopydocker stop earthsync-server earthsync-postgresdocker rm earthsync-server earthsync-postgresdocker volume rm earthsync\_data_\# Restart as above_

    *   **Kubernetes**:bashWrapCopykubectl delete -f earthsync-k8s.yamlkubectl apply -f earthsync-k8s.yaml

*   **Connection Issues**: Verify .env (Docker) or Secret (Kubernetes) matches service names and credentials.

*   **Permissions**: Avoid sudo by adding your user to the docker group:bashWrapCopysudo usermod -aG docker $USERnewgrp docker

*   **Kubernetes Access**: Use kubectl port-forward or adjust Service type if LoadBalancer isn't accessible.

Notes

-----

*   **No Heroku**: Deployment is strictly Docker- or Kubernetes-based.

*   **Port**: Defaults to 3000; modify in .env (Docker) or manifest (Kubernetes) if needed.

*   **Persistence**: Uses Docker volumes (earthsync\_data, earthsync\_redis\_data) or Kubernetes PVCs (postgres-pvc, redis-pvc).