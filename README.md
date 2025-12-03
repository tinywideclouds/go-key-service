# **Go Key Service**

This service acts as a simple, authenticated, and scalable storage solution for user public keys, backed by Firestore. It serves as the authoritative store for the "Sealed Sender" encryption model.

## **Architecture & Security**

This service implements a **"Claim-to-Write"** binding protocol to prevent identity spoofing.

* **Dual-Write Guarantee:** When a user uploads keys, the service automatically writes them to **both** the stable Identity URN (`urn:auth:...`) and the discoverable Handle URN (`urn:lookup:...`) found in the JWT.
* **JWT Binding:** Writes are only permitted if the authenticated user's token contains specific claims verified by the Identity Service.

### **Network Configuration**
The service listens on `/keys/{entityURN}`.
It is typically deployed behind a reverse proxy (e.g., Nginx) that maps the client route `/api/keys/*` to the internal route `/keys/*`.

## **Configuration**

Configuration is managed via a YAML file (e.g., `local.yaml`), which can be overridden by environment variables.

```yaml
# local.yaml
run_mode: "local"
project_id: "your-gcp-project"
http_listen_addr: ":8081"
identity_service_url: "http://localhost:3000"
firestore_collection: "public-keys"
cors:
  allowed_origins:
    - "http://localhost:4200"
```

### **Environment Variables**

* GCP\_PROJECT\_ID: Overrides project\_id.  
* IDENTITY\_SERVICE\_URL: The root URL of the identity service for OIDC discovery/JWKS validation.

---

## **API Endpoints**

### **GET /keys/{entityURN}**

Retrieves the public encryption and signing keys for a given entity URN.

* **Auth:** Public (No JWT required).  
* **Response (200 OK):**  
 ```` JSON  
  {  
    "encKey": "AQIDBAUGBwgJCgsMDQ4PEA==",  
    "sigKey": "EAECAwQFBgcICQoLDA0ODw=="  
  }
````
* **Response (404 Not Found):** The user exists but has not uploaded keys.

### **POST /keys/{entityURN}**

Stores (or overwrites) the public keys for the authenticated user.

* **Auth:** Requires a valid Bearer token (RS256).  
* **Authorization Rule:** The JWT must contain a sub (UserID) or handle (Lookup URN) that matches the {entityURN} in the path.  
* **Behavior:** A successful request triggers a transaction that updates keys for **ALL** identities linked to that token (e.g., both the Google ID and the Email Handle).

**Request Body:**

JSON
````
{  
  "encKey": "AQIDBAUGBwgJCgsMDQ4PEA==",  
  "sigKey": "EAECAwQFBgcICQoLDA0ODw=="  
}
````
**Response:** 201 Created (Empty body).
