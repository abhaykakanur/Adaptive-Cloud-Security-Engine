Adaptive Cloud Security Engine
Intelligent Self-Healing Zero-Trust Secure Cloud Platform
An adaptive, risk-driven cloud security backend that dynamically adjusts encryption strength, distributes cryptographic keys, detects anomalous behavior using entropy analysis, and performs automated self-healing to eliminate single-point compromise risks.

Table of Contents

Overview
Core Architecture
Tech Stack
Security Model
File Lifecycle
Storage Tier Rotation
Authentication and Authorization
Threat Model Coverage
Project Structure
Setup Instructions
API Endpoints
Enterprise Upgrade Roadmap
Why This Project Matters


Overview
The Adaptive Cloud Security Engine is a backend security framework built using FastAPI that provides the following capabilities:

Risk-based dynamic encryption with 2, 3, or 5 key splitting
Distributed cryptographic key storage across multiple storage layers
Behavioral anomaly detection based on user and request patterns
Entropy-based self-attack monitoring for detecting predictable security behavior
Automated self-healing mechanisms for incident response
Secure JWT-based authentication with token versioning
Role-based authorization separating admin and user access
AWS S3 encrypted storage integration with dynamic tier rotation

This system is designed to simulate enterprise-level adaptive security architecture while remaining software-based and infrastructure-efficient.

Core Architecture
The system follows a layered pipeline from user request through risk evaluation to secure storage and retrieval:
User
  -> FastAPI Backend
    -> Risk Engine
      -> Encryption Engine
        -> Key Splitter
          -> Distributed Key Storage (S3 + DB + User Layer)
            -> Self-Healing Engine
              -> Entropy Monitor
                -> Secure File Retrieval
Each layer operates independently and communicates through well-defined internal interfaces, ensuring that a failure or compromise at any single layer does not cascade through the entire system.

Tech Stack
Backend
ComponentTechnologyPurposeAPI FrameworkFastAPIHigh-performance REST API with async supportASGI ServerUvicornProduction-grade server for FastAPIRuntimePython 3.10+Core language
Security and Cryptography
ComponentTechnologyPurposeFile EncryptionAES-256Symmetric encryption for stored filesToken SigningHMAC-SHA256 via JWTSecure authentication token generationKey DistributionShamir-style Secret SharingSplitting cryptographic keys into N partsPassword Storagebcrypt hashingSecure credential storage
Cloud and Storage
ComponentTechnologyPurposeObject StorageAWS S3Encrypted remote file storageStorage ClassesSTANDARD / STANDARD_IADynamic tier rotation based on riskRelational DatabasePostgreSQL (production) / SQLite (development)User metadata and key fragment storageORMSQLAlchemyDatabase abstraction layer
Security Intelligence
ComponentPurposeBehavioral Risk EngineClassifies request risk based on contextual signalsIP AnalysisDetects geographic or network-level anomaliesDevice FingerprintingHashes User-Agent strings to detect session hijackingEntropy-Based Anomaly DetectionMonitors randomness in access and encryption patterns

Security Model
1. Dynamic Risk-Based Encryption
The system evaluates every action (login, upload, download) and classifies the associated risk level. Encryption key distribution is adjusted dynamically based on this classification:
Risk LevelKey PartsStorage DistributionLOW2AWS S3 + DatabaseMEDIUM3AWS S3 + Database + User LayerHIGH5AWS S3 + Database (multiple entries) + User Layer
Encryption strength scales automatically with detected risk without requiring manual intervention.
2. Distributed Key Storage
Rather than storing all key parts in a single location, the system distributes key fragments across independent storage layers:

Part 1 is stored in AWS S3
Part 2 is stored in the relational database
Part 3 is encrypted within the user record itself

Key reconstruction occurs only during an authenticated download flow. This eliminates single-point key compromise: an attacker who gains access to one storage layer cannot reconstruct the encryption key without compromising all others simultaneously.
3. Behavioral Risk Engine
The risk engine evaluates the following signals per request:

IP address changes between sessions
Device fingerprint variations (User-Agent hashing)
Failed login attempt frequency
File size and file type anomalies
Login timing patterns and frequency

The engine outputs one of three classifications: LOW, MEDIUM, or HIGH, which drives all downstream encryption and storage decisions.
4. Entropy-Based Anomaly Detection
The entropy monitor observes the randomness of the following system behaviors:

Access pattern distributions across files and endpoints
Encryption tier change frequency and regularity
Security decision predictability over rolling time windows

If entropy drops below a configured threshold, indicating that behavior has become predictable or systematic (a signal associated with reconnaissance or automated attack activity), self-healing is triggered automatically.
5. Self-Healing Engine
Upon detecting a compromise signal, the self-healing engine executes the following actions automatically:

JWT token invalidation via token version bump
Temporary account locking
Trust score reset for the affected user
Storage tier hardening (promotion to higher security tier)
Audit log entry creation with full context

Compromised sessions are revoked immediately without requiring manual administrator action.

File Lifecycle
Upload Flow

User is authenticated via JWT bearer token
Risk engine evaluates the request context and assigns a risk level
File is encrypted using AES-256
Encryption key is split into N parts (2, 3, or 5 depending on risk level)
Key parts are distributed across AWS S3, the database, and the user record
Encrypted file is stored in AWS S3 under the appropriate storage class
Audit log is updated with the operation record

Download Flow

JWT token is verified and token version is validated
Key parts are fetched from all distributed storage locations
Encryption key is reconstructed from key fragments
File is decrypted in memory
Secure streaming response is returned to the authenticated user


Storage Tier Rotation
Encrypted files are dynamically rotated between AWS S3 storage classes based on system signals:
Storage ClassTrigger ConditionSTANDARDNormal risk level, recent active accessSTANDARD_IAElevated risk, suspicious activity, self-heal event
Tier rotation is handled automatically by the storage manager based on risk engine output and self-healing triggers. No manual storage management is required.

Authentication and Authorization

Authentication uses the OAuth2 password flow with JWT bearer tokens
Token signing uses HMAC-SHA256 with a configurable secret
Token versioning enables instant session revocation without a token blacklist: incrementing the version invalidates all previously issued tokens for a user
Authorization is role-based, with two roles: admin and user

Admin users have access to user management and audit log endpoints
Standard users are restricted to their own files and account




Threat Model Coverage
ThreatMitigationAWS S3 BreachKey parts are distributed; S3 alone cannot reconstruct the keyDatabase BreachKey fragments stored in the database are encryptedToken TheftToken version invalidation immediately revokes stolen tokensBrute Force AttackAccount locking and self-healing activation on repeated failuresInsider AttackRisk scoring and audit logging capture all access eventsPredictable Security BehaviorEntropy detection triggers self-healing before exploitation

Project Structure
adaptive-cloud-security/
|
+-- app/
|   +-- main.py               # Application entry point and route registration
|   +-- database.py           # Database engine and session configuration
|   +-- models.py             # SQLAlchemy ORM models
|   +-- auth.py               # JWT authentication and authorization logic
|   +-- security/
|       +-- encryption.py     # AES-256 encryption and decryption
|       +-- key_splitter.py   # Shamir-style key splitting and reconstruction
|       +-- risk_engine.py    # Behavioral risk classification
|       +-- entropy_engine.py # Entropy monitoring and anomaly detection
|       +-- storage_manager.py# S3 storage operations and tier rotation
|
+-- .env                      # Environment variable configuration
+-- requirements.txt          # Python dependency manifest
+-- audit.log                 # Append-only audit trail
+-- README.md

Setup Instructions
1. Clone the Repository
bashgit clone https://github.com/yourusername/adaptive-cloud-security.git
cd adaptive-cloud-security
2. Create a Virtual Environment
bashpython -m venv venv
source venv/bin/activate       # On Windows: venv\Scripts\activate
3. Install Dependencies
bashpip install -r requirements.txt
4. Configure Environment Variables
Create a .env file in the project root with the following variables:
envAWS_ACCESS_KEY_ID=your_aws_access_key
AWS_SECRET_ACCESS_KEY=your_aws_secret_key
AWS_REGION=your_aws_region
AWS_BUCKET_NAME=your_s3_bucket_name
JWT_SECRET=your_jwt_secret_key
DATABASE_URL=postgresql://user:password@localhost/dbname
For local development with SQLite, set:
envDATABASE_URL=sqlite:///./dev.db
5. Initialize the Database
bashpython -c "from app.database import Base, engine; from app import models; Base.metadata.create_all(bind=engine)"
6. Start the Server
bashuvicorn app.main:app --reload --port 8000
The interactive API documentation will be available at:
http://127.0.0.1:8000/docs

API Endpoints
Authentication
MethodEndpointDescriptionPOST/registerRegister a new user accountPOST/loginAuthenticate and receive a JWT tokenGET/meRetrieve the authenticated user's profile
File Operations
MethodEndpointDescriptionPOST/uploadUpload and encrypt a fileGET/download/{filename}Download and decrypt a fileGET/filesList all files belonging to the authenticated userDELETE/delete/{filename}Delete a file and its associated key parts
Administration
MethodEndpointDescriptionAccessGET/admin/usersList all registered users with metadataAdmin onlyGET/admin/logsRetrieve the full audit logAdmin only
All protected endpoints require a valid JWT bearer token in the Authorization header.

Enterprise Upgrade Roadmap
The following enhancements are planned for future releases to move the system toward full production-grade enterprise deployment:
EnhancementDescriptionAWS KMS IntegrationDelegate key management to AWS Key Management Service for hardware-backed securityZero-Trust Continuous VerificationRe-verify identity and device trust on every request, not just at loginML-Based Anomaly DetectionReplace rule-based risk scoring with trained behavioral modelsKubernetes DeploymentContainer orchestration with horizontal scaling and pod-level isolationOpenTelemetry TracingDistributed tracing across all security pipeline stagesELK Audit DashboardElasticsearch, Logstash, and Kibana stack for real-time audit visualizationMulti-Region ReplicationReplicate encrypted objects and key fragments across AWS regionsClient-Side EncryptionIntegrate WebCrypto API so files are encrypted before leaving the browser

Why This Project Matters
The Adaptive Cloud Security Engine demonstrates several advanced security engineering principles that are directly applicable to production cloud systems:
Adaptive security architecture — the system does not apply a fixed security policy. It evaluates context at runtime and adjusts encryption strength, key distribution, and storage behavior dynamically, reflecting how modern zero-trust systems operate.
Defense-in-depth key management — by distributing key fragments across independent storage systems, the design ensures that no single breach (S3, database, or user record) is sufficient to compromise encrypted data. This directly mirrors enterprise key management practices.
Real-time behavioral analysis — the risk engine and entropy monitor operate on every request, providing continuous rather than periodic security evaluation. This reduces the window between compromise and detection.
Automated incident response — the self-healing engine eliminates the delay between detection and remediation. Token revocation, account locking, and storage hardening occur without human intervention.
Distributed cryptographic design — the key splitting approach demonstrates practical application of secret sharing schemes in a cloud-native context, bridging academic cryptography with deployed infrastructure engineering.
This project serves as both a functional backend security system and a reference implementation for adaptive, self-defending cloud architectures.
