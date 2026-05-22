# PKI Backend - Public Key Infrastructure

> Academic project for *Security in Electronic Commerce Systems*, 2025

<p align="left">
  <a href="https://github.com/HakTak/sentinel-pki-password-vault-frontend"><img src="https://img.shields.io/badge/Repository-Frontend-7A8C5E?style=for-the-badge&logo=github" alt="Frontend Repo"/></a>
</p>

---

## 📖 Quick Start

**⏭️ Skip shared information below** if you already know the PKI project structure. Jump directly to **[Backend-Specific Section](#-backend-specific-section)** below.

---

## 🔗 Shared Project Information

### About the Project

Complete implementation of a **Public Key Infrastructure (PKI)** system for managing digital certificates with:

- 🔐 **Secure Authentication** - JWT, reCAPTCHA, multi-device sessions
- 📜 **Certificate Management** - Issuance, viewing, revocation
- 🔑 **Shared Password Manager** - Web Crypto API, client-side encryption
- 👥 **Access Control** - Administrator, CA user, regular user
- 📊 **Audit Logs** - Activity tracking
- 🛡️ **Attack Protection** - SQL injection, XSS, CSRF protection

### User Roles

- **👤 Administrator** - Full system control
- **🏢 CA User** - Manage certificates for their organization
- **👥 Regular User** - Request end-entity certificates

### Security Measures

- ✅ HTTPS/TLS encryption
- ✅ JWT authentication with refresh tokens
- ✅ reCAPTCHA protection
- ✅ Multi-device session tracking
- ✅ Encrypted password storage (PBKDF2/AES)
- ✅ SQL injection & XSS protection
- ✅ Comprehensive audit logging
- ✅ Input validation & sanitization

---

## 🔧 Backend-Specific Section

### Key Features

#### Certificate Management
- ✅ Issuance of all certificate levels (Root, Intermediate, End-Entity)
- ✅ CA certificate storage with private keys in keystore
- ✅ CSR (Certificate Signing Request) support
- ✅ Certificate Revocation with CRL/OCSP
- ✅ Certificate templates with predefined extensions

#### Authentication & Security
- ✅ JWT token-based authentication
- ✅ reCAPTCHA protection on login
- ✅ Multi-device session tracking
- ✅ Key encryption (PBKDF2/AES)
- ✅ Account recovery with time-limited links
- ✅ Role-based access control (RBAC)

#### Shared Password Manager
- ✅ Secure sensitive data storage
- ✅ Public key encryption
- ✅ Password sharing with other users
- ✅ Server-side encrypted storage

### Technical Stack

- **Framework**: Spring Boot 3.x
- **Database**: MySQL/PostgreSQL (configured in `application.properties`)
- **Build Tool**: Maven
- **Security**: Spring Security, JWT, SSL/TLS
- **Certificates**: Java Keytool, X.509 standard
- **Language**: Java 17+

### Prerequisites

- ☕ Java 17 or higher
- 📦 Maven 3.6+
- 🗄️ MySQL or PostgreSQL database
- 🔑 OpenSSL for CSR/key generation (optional)

### Installation & Setup

#### 1. Clone & Build

```bash
git clone <backend-repo-url>
cd pki-back
mvn clean install
```

#### 2. Configuration

Edit `src/main/resources/application.properties`:

```properties
# Database Connection
spring.datasource.url=jdbc:mysql://localhost:3306/pki_db
spring.datasource.username=root
spring.datasource.password=your_password

# JWT Configuration
app.jwt.secret=your_secret_key_must_be_at_least_256_bits_long
app.jwt.expiration=86400000

# reCAPTCHA (Google reCAPTCHA)
recaptcha.secret.key=your_recaptcha_secret_key

# Email Configuration (for activation links)
spring.mail.host=smtp.gmail.com
spring.mail.port=587
spring.mail.username=your_email@gmail.com
spring.mail.password=your_app_password

# HTTPS Configuration
server.ssl.key-store=classpath:keystore.jks
server.ssl.key-store-password=your_keystore_password
server.ssl.key-store-type=JKS
```

#### 3. Running the Application

```bash
# Using Maven
mvn spring-boot:run

# Or run JAR directly
java -jar target/sertifikat-0.0.1-SNAPSHOT.jar
```

The application will be available at `https://localhost:8080`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh-token` - Refresh JWT token
- `POST /api/auth/logout` - User logout
- `POST /api/auth/forgot-password` - Password recovery request

### User Management
- `GET /api/users/profile` - Get user profile
- `PUT /api/users/profile` - Update user profile
- `GET /api/users/sessions` - Get active sessions
- `DELETE /api/users/sessions/{tokenId}` - Revoke session token
- `GET /api/users/public-keys` - Get user public keys

### Certificates
- `GET /api/certificates` - List certificates (by privilege)
- `POST /api/certificates/generate` - Generate new certificate
- `GET /api/certificates/{id}` - Get certificate details
- `POST /api/certificates/{id}/revoke` - Revoke certificate
- `GET /api/certificates/{id}/download` - Download certificate

### CSR (Certificate Signing Request)
- `POST /api/csr/upload` - Upload CSR and private key
- `GET /api/csr/{id}` - View CSR request

### Templates (CA users)
- `GET /api/templates` - List templates
- `POST /api/templates` - Create template
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template

### Password Manager
- `GET /api/secrets` - List saved passwords
- `POST /api/secrets` - Save new password
- `DELETE /api/secrets/{id}` - Delete password
- `POST /api/secrets/{id}/share` - Share password with user

## Project Structure

```
pki-back/
├── src/
│   ├── main/
│   │   ├── java/com/bezbednost/sertifikat/
│   │   │   ├── SertifikatBackendApplication.java      # Main class
│   │   │   ├── config/
│   │   │   │   └── SecurityConfig.java                # Spring Security config
│   │   │   ├── controller/                             # REST controllers
│   │   │   ├── service/                                # Business logic
│   │   │   ├── model/                                  # JPA entities
│   │   │   ├── dto/                                    # Data Transfer Objects
│   │   │   ├── repository/                             # Database access
│   │   │   ├── utils/                                  # Utility classes
│   │   │   ├── validator/                              # Input validators
│   │   │   └── exception/                              # Custom exceptions
│   │   └── resources/
│   │       ├── application.properties                  # Configuration
│   │       ├── logback-spring.xml                      # Logging config
│   │       └── templates/
│   └── test/
│       └── java/com/bezbednost/sertifikat/
├── data/
│   └── keystores/                                      # Keystore files
├── logs/                                               # Application logs
├── pom.xml                                             # Maven dependencies
└── mvnw / mvnw.cmd                                     # Maven wrapper
```

## Key Classes

### SecurityConfig.java
Spring Security configuration:
- Definition of secure and public routes
- JWT filter for token validation
- CORS configuration
- HTTPS enforcement

### SubjectService.java
Business logic for user and certificate management

### SubjectController.java
REST API endpoints for user management

### CertificateService.java
Certificate generation, storage, and revocation logic

## Database Entities

Required entities:
- `User` - System users
- `Certificate` - Certificates
- `CertificateTemplate` - Certificate templates
- `Secret` - Password manager entries
- `AuditLog` - Activity logs
- `UserSession` - Active JWT sessions
- `Revocation` - Revoked certificate records

## Logging

The system uses `logback-spring.xml` for logging configuration:
- **Level**: INFO (DEBUG for development)
- **Rotation**: Daily log rotation
- **Location**: `logs/` directory
- **Format**: ISO-8601 timestamp, level, logger name, message

Logging examples:
```log
2025-05-22 10:15:30,123 INFO  - User 'alice@example.com' logged in successfully
2025-05-22 10:16:45,234 WARN  - Certificate revocation requested for CN=server.example.com
2025-05-22 10:17:12,345 ERROR - Failed to generate certificate: Invalid CSR format
```

## Security Recommendations

1. **Key Storage**
   - Generate random password for each keystore
   - Encrypt keystore passwords using PBKDF2/AES
   - Never store private keys on the frontend

2. **Input Validation**
   ```java
   // Use PreparedStatements for SQL queries
   // Validate and sanitize all user inputs
   // Escape HTML/JS code when displaying user data
   ```

3. **HTTPS & Certificates**
   ```bash
   # Generate test certificate (development)
   keytool -genkeypair -alias tomcat -keyalg RSA -keysize 2048 \
           -keystore keystore.jks -validity 365
   ```

4. **JWT Token Security**
   - Use `HS256` or `RS256` algorithm
   - Set short expiration time (15-60 minutes)
   - Implement refresh token mechanism
   - Store tokens in HttpOnly cookies only

## Development

### Testing API Endpoints

```bash
# Using Postman or curl
curl -X POST https://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"password123"}'
```

### Debug Mode

```bash
mvn spring-boot:run -Dspring-boot.run.arguments="--debug"
```

### Run Tests

```bash
# Unit tests
mvn test

# Integration tests
mvn verify

# With code coverage
mvn test jacoco:report
```

## Deployment

### Production Build

```bash
mvn clean package -DskipTests
```

Run with optimized memory settings:
```bash
java -Xmx1024m -Xms512m -jar target/sertifikat-0.0.1-SNAPSHOT.jar
```

### Docker Deployment

```dockerfile
FROM openjdk:17-jdk-slim
WORKDIR /app
COPY target/sertifikat-0.0.1-SNAPSHOT.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java","-Xmx1024m","-Xms512m","-jar","/app.jar"]
```

Build and run:
```bash
docker build -t pki-backend .
docker run -p 8080:8080 pki-backend
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| SSL handshake error | Check `keystore.jks` and `application.properties` configuration |
| JWT token expired | Implement refresh token mechanism |
| Database connection failed | Verify `spring.datasource` configuration |
| CORS error | Update `SecurityConfig` with correct frontend URL |
| Port 8080 already in use | Change port in `application.properties`: `server.port=8081` |

## Advanced Features (Bonus)

- 🔑 Keycloak integration for SSO
- 📱 2FA with authenticator app
- 🔍 Vulnerability analysis with Sonar/Codacy/Snyk
- 📊 Monitoring with Prometheus/Grafana

## Documentation

- [X.509 Standard](https://tools.ietf.org/html/rfc5280)
- [Spring Security Documentation](https://spring.io/projects/spring-security)
- [Spring Boot Documentation](https://spring.io/projects/spring-boot)
- [JWT.io](https://jwt.io/)
- [Maven Documentation](https://maven.apache.org/)

## License

Academic project - Security in Electronic Commerce Systems, 2025

---

**Last Updated**: May 2026  
**Version**: 1.0.0  
**Status**: In Development
