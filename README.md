# Go Key Service

This service acts as a simple, authenticated, and scalable storage solution for user public keys, backed by Firestore.

## Configuration

This service is configured via a YAML file (e.g., `local.yaml`) and environment variables.

```yaml
# local.yaml
run_mode: "local"
project_id: "your-gcp-project"
http_listen_addr: ":8081"
identity_service_url: "http://localhost:3000"
cors:
  allowed_origins:
    - "http://localhost:4200"
````

### **Environment Variables**

Environment variables will override values from the YAML file.

* GCP\_PROJECT\_ID: (Required) The Google Cloud project ID.
* IDENTITY\_SERVICE\_URL: (Required) The root URL of the identity service for OIDC discovery (e.g., http://identity-service.default.svc.cluster.local).
* JWT\_SECRET: (Required) The JWT secret used by the authentication middleware.

---

## **API Endpoints**

### **V2 API (Sealed Sender Model)**

This is the primary API for storing and retrieving keys compatible with the "Sealed Sender" model. It uses camelCase JSON.

#### **GET /api/v2/keys/{urn}**

Retrieves the public encryption and signing keys for a given entity URN. This is a public endpoint.

**Response (200 OK):**

JSON

{  
"encKey": "AQIDBAUGBwgJCgsMDQ4PEA==",  
"sigKey": "EAECAwQFBgcICQoLDA0ODw=="  
}

#### **POST /api/v2/keys/{urn}**

Stores (or overwrites) the public encryption and signing keys for an entity. This endpoint requires authentication, and the authenticated user's ID *must* match the {urn} in the path.

**Request Body:**

JSON

{  
"encKey": "AQIDBAUGBwgJCgsMDQ4PEA==",  
"sigKey": "EAECAwQFBgcICQoLDA0ODw=="  
}

Response (201 Created):  
(Empty body)

---

### **V1 API (Legacy)**

**Deprecated:** These endpoints are for legacy clients only. They do not support the sigKey required by the "Sealed Sender" model. New applications should use the V2 API.

#### **GET /keys/{urn}**

Retrieves a single raw encKey blob (application/octet-stream).

#### **POST /keys/{urn}**

Stores a single raw encKey blob (application/octet-stream). Requires authentication.