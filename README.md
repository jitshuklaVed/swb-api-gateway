# swb-api-gateway

> Spring Cloud API Gateway routing traffic to microservices via Eureka

Part of the **Swarn Bharat Media** microservices ecosystem.

## 🚀 Service Overview
- **Service Name:** `api-gateway`
- **Default Port:** `8080`
- **Java Version:** `17`
- **Framework:** Spring Boot `3.4.5` & Spring Cloud `2024.0.1`

---

## 💻 Local Development Setup

### Prerequisites
- JDK 17 or higher
- Maven 3.8+
- Running Eureka Service Registry (`http://localhost:8761`)
- Running PostgreSQL database (or use embedded H2 for quick testing)

### Run Locally
```bash
# 1. Clean and build
mvn clean install

# 2. Start the service
mvn spring-boot:run
```

Service will be accessible at:
- **Direct Port:** `http://localhost:8080`
- **Via Gateway:** `http://localhost:8080` (see Gateway routing rules)

---

## 🐳 Docker Setup

### Build Docker Image
```bash
docker build -t smapp/api-gateway:1.0.0 .
```

### Run Container
```bash
docker run -d --name api-gateway -p 8080:8080 smapp/api-gateway:1.0.0
```

---

## 🔒 Permission & Access Control
Access to this repository is restricted to developers assigned to the `api-gateway` team.
For local full-stack testing without access to other service repos, use the **`swb-orchestration`** repository which runs dependent services as pre-built Docker containers.
