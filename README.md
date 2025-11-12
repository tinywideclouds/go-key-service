# **Go Key Service**

This service acts as a simple, authenticated, and scalable storage solution for user public keys, backed by Firestore.

## **Configuration**

This service is configured via a YAML file (e.g., local.yaml) which can be partially overridden by environment variables.

YAML
````
\# local.yaml  
run\_mode: "local"  
project\_id: "your-gcp-project"  
http\_listen\_addr: ":8081"  
identity\_service\_url: "http://localhost:3000"  
firestore\_collection: "public-keys"  
cors:  
  allowed\_origins:  
    \- "http://localhost:4200"
````
### **Environment Variables**

Environment variables will override values from the YAML file.

* GCP\_PROJECT\_ID: (Override) The Google Cloud project ID.  
* IDENTITY\_SERVICE\_URL: (Override) The root URL of the identity service for OIDC discovery (e.g., http://identity-service.default.svc.cluster.local).

---

## **API Endpoints**

The service provides a JSON-based API for storing and retrieving public keys compatible with the "Sealed Sender" model.

### **GET /keys/{entityURN}**

Retrieves the public encryption and signing keys for a given entity URN. This is a public endpoint.

**Response (200 OK):**

JSON
````
{  
  "encKey": "AQIDBAUGBwgJCgsMDQ4PEA==",  
  "sigKey": "EAECAwQFBgcICQoLDA0ODw=="  
}
````
### **POST /keys/{entityURN}**

Stores (or overwrites) the public encryption and signing keys for an entity. This endpoint requires authentication, and the authenticated user's ID *must* match the ID in the {entityURN} path.

**Request Body:**

JSON
````
{  
  "encKey": "AQIDBAUGBwgJCgsMDQ4PEA==",  
  "sigKey": "EAECAwQFBgcICQoLDA0ODw=="  
}

Response (201 Created):  
(Empty body)
````