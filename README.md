
# DID Messaging API

This repository contains documentation for a NestJS-based API that enables decentralized identity (DID) management and secure message exchange using DIDComm over Hyperledger Aries agents and the BC Gov VON network.

The API allows project components (orchestrators, devices, services, pilots) to:

- register decentralized identities (DIDs)  
- authenticate via JWT  
- establish pairwise DIDComm connections  
- exchange encrypted DIDComm messages  
- retrieve and decrypt messages through ACA-Py  

---

## Overview

The system provides:

- **Decentralized Identifiers (DIDs)** for each registered user/service  
- **Aries-based DIDComm** channels between two participants  
- **Secure encrypted messaging**, with encryption handled internally by **ACA-Py** agents  
- **REST endpoints** for registration, authentication, connection setup, message exchange  
- **Metadata-only storage** in the database (no plaintext messages)  

Plaintext message content is *never stored* — only encrypted envelopes and metadata.

---

## Architecture

### **Components**

### **1. ACA-Py Agents**
- One agent per role (e.g., sender, recipient)  
- Manage DIDs, endpoints, pairwise DIDComm connections  
- Perform encryption/decryption internally  
- Expose admin API for DID and connection operations  

### **2. NestJS API Layer**
- Public REST interface for all pilot components  
- Integrates with ACA-Py admin endpoints  
- Handles:
  - user registration  
  - authentication (JWT)  
  - DIDComm connection establishment  
  - message routing  
  - metadata persistence  

### **3. Database**
Stores **only**:
- user metadata (email, label, DID, role, agent URL)  
- encrypted message envelopes  
- timestamps + routing info  

### **4. VON Network (Optional)**
- Used for DID/NYM anchoring  
- Trust registry operations  

## High-Level DIDComm Flow

1. **Register a user**  
   - Creates a new DID and assigns an ACA-Py agent  
   - Stores user metadata  

2. **Authenticate**  
   - Client receives JWT access token  

3. **Establish connection**  
   - Sender creates DIDComm invitation  
   - Recipient accepts it  
   - A secure pairwise DIDComm channel is formed  

4. **Send DIDComm message**  
   - Sender submits plaintext via API  
   - ACA-Py encrypts and routes the message  

5. **Receive & decrypt**  
   - Recipient fetches encrypted envelopes  
   - ACA-Py decrypts them on `/unpack` request  

---
## Useful Links

**Swagger API:**  
https://did.zentrix.io/api  

**Implementation repository:**  
https://github.com/ZentrixLab/didcomm/tree/dev
