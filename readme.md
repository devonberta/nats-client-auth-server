# Client Auth Server
This service seeks to solve a chicken or the egg problem that exists with registering clients in nats without out of bound distribution of keys.

The problem and potential solution suggested here in the JWT in depth guide:
https://docs.nats.io/running-a-nats-service/nats_admin/security/jwt#account-based-setup

Some inspiration for components and functionality of this implementation come from Hashicorps secret zero solution approach as reference below. We do not implement seal wrapping but we do implement the idea of seperating the context of retrieval identification from the credential itself. Providing something that we can audit and manage to ensure the integrity of the credential retrieval process: (No hashicorp tooling is required to use this server. Am just giving credit where credit is due for the inspiration around approaches in designing this service.)
https://www.hashicorp.com/en/resources/vault-response-wrapping-makes-the-secret-zero-challenge-a-piece-of-cake

# Challenges in implementing:
The suggested solution creates a few security problems for us because of the suggested shared account:
1. A request and reply pattern as seen with a service or even an async publish and respond flow here can result in leaking of credentials as any client can read the responses of other clients. This occurs because Publish permission and Subscribe permissions will be the same for the shared user.
2. Depending on the message structure the system maybe susceptible to replay attacks

# How we address this:
The solution for addressing this is as follows:
1. each client generates its private and public key pair locally
2. The server provides its public key via a request subject so that clients can read it for use in encryption of requests
3. Clients create requests encrypting their request to the server and including their public key in the payload. The client request includes a unique response inbox for that client.
4. Responses from the server are encrypted using the clients public key and sent to their unique response inbox. Other clients can read the response but cannot decrypt the response which means the payload can only be used by the requesting system.
5. The entire payload that will include the private key, data signature, request uuid and request related fields is encrypted which means even if replayed the client public key cannot be replaced which will be used in encrypting the response object. The request uuid can be used to quickly and easily determine if message has already been processed and discard if it has been. 
6. To enable for autoamation of the process and not block on approving clients manually we can include a variety of metadata and role-token field which can be used to authorize the request in a limited time safe manner without impacting operations of the system. The role token or other metadata fields can be used to approve requests because the auth service can be informed of what rules to use for automated approvals such as known client uuid, metadata fields, role token, and issuance history. These factors can be used to assign permissions relevant to the context that the client is running in (operating system, runtime type, location) as to enable client specific services to be available outside of service specific permissions. Service specific permsissions should be tied to the client uuid or role token values specifically to enforce least privelege on clients.
7. Role tokens can be issued for process automation purposes and should include a TTL value. They should be automatically rotate in provisioning processes before their expiration time. The role token itself is only used as part of initial validation to auto approve a request. It provides no direct access to any resource in NATS. The TTL nature of this is meant to enforce regular rotation and ensure integrity of provisioning process of resources in the case of compromise or leakage of the value. The provisioning process itself should have an issued crednetial allowing it to retrieve the role token for the context it is managing at a regular interval (kubernetes sidecar refreshing a secret value that pods use). This value is only relevant during the initial client registration request process and is not relevant during renewal or refresh processes. As such it can be rotate at any time without impacting existing or future services coming online. Role tokens with TTL's configured will automatically rotate on the server side half way through their TTL to allow time for provisioning processes to update to the new value prior to expiration of the old value. During this time both tokens are valid until the old tokens TTL has been exceeded.
# why do we care?
The process of provisioning users / clients of nats needs to be secure and automated to allow us to ensure integrity, availability and confidentiality of the NATS system.
* Manual credential creation and distribution creates operational, security and scale challenges in your application. Revocation becomes tedious and impactful to your service when required. Implementing an automated workflow that accounts for the operational requirements of updating these credentials quickly and securely alleviates operational challenges and improves security posture.
* In this solution the private keys are created and never leave the client in most use cases. This eliminates a variety of supply chanin / provisioning attack vectors that could compromise your clients credentials.
* We provide a mechanism through roles to and metadata rules to apply fine grained context aware permissions to the client for the environment or platform they are running on. This allows for more dynamic and intelligent client behavior while maintianing least privelege models.
* Permission updates need to be enforced in a timely manner. Being able to effectively trigger rotation of client credentials is crucial to enforcing changed permissons. Old permissions will remain in effect until a client reconnects. This solution provides mechanisms to force client refresh behavior quickly and little to no service interruption.
# workflows:
The workflows below breakdown the various different operations in order to create clarity around the implementation and how it operates in each case. A variety of diagrams and documentation structures are used to help clarify concepts that may not be easy to communicate in one format or another. These include:
1. process table with stated responsibility of the action (service, client, nats)
2. simplified sequence diagram that covers the board overall process of an action
3. detailed sequence diagram that covers each interaction in a workflow
4. flow chart showing the data processing order of each component
## register client
### process table
| step | name | description | responsible |
|------|------|-------------|-------------|
|  1 | check credentials | startup sequence checks local credentials | client |
|  2 | connect to auth service | nats connection to auth account | client |
|  3 | request auth public key | retrieve auth public key from key value store | client |
|  4 | generate keys | generate public key pair | client |
|  5 | generate registration object | build registration object with key an system information, create signature for data in object | client |
|  6 | encrypt object data with auth service public key | encrypting data for transit and to prevent snooping | client |
|  7 | submit registration request | nats request / publish | client |
|  8 | recieve registration | parse registration requests | auth service |
|  9 | read and store reply header | parse message and headers, storing reply inbox | auth service
| 10 | decrypt payload | decrypt message data with auth service private key | auth service |
| 11 | validate data signature | validate payload data signature matches using public key | auth service |
| 12 | read payload values | read role-token, client-uuid, metadata | auth service |
| 13 | generate jwt | create jwt with permissions based on matches | auth service |
| 14 | store jwt | store jwt in key value store | auth service |
| 15 | encrypt response | encrypte response with client public key | auth service
| 16 | insert jwt to response | add jwt to response payload | auth service |
| 17 | read reply inbox | read back reply inbox for response | auth service |
| 18 | respond | send response to reply inbox | auth service |
| 19 | retrive | client recieves response from inbox | client |
| 20 | decrypt | decrypt response with private key | client |
| 21 | parse response | parse and store jwt response | client |
| 22 | connect to applicaiton account | use jwt to create nats connection to applicaiton acount | client |
| 23 | consume services | client consumes services as part of running applicaiton | client |
### simplified sequence
``` mermaid
sequenceDiagram
client <<->> startup: 1. checks credentials
client ->> auth service: 2. send encrypted registration request
auth service <<->> backend logic: 3. decrypt, validate, and generate credential
auth service ->> client: 4. respond with credential
client <<->> validate crednetial: 5. client validates response
client ->> application account: 6. Client connects to applicaiton account with new credential
```
### detailed sequence
``` mermaid
sequenceDiagram
client ->> credentials: 1. client checks if credentials exist
credentials ->> client: 2. client has no credential
client ->> public-key-kv: 3. request for public key from kv
public-key-kv ->> client : 4. client recieves public key
client ->> payload: 5. client generates registration payload and encrypts wiht public key
payload ->> auth-service: 6. request to auth service with payload
auth-service <<->> validation: 7. validate request and process it
auth-service ->> response: 8. generate response and encrypts with client public key
response ->> client: 9. client recieves response and decrypts it
client ->> nats-account: 10. client uses credential to connect to nats account
```
### flowchart
``` mermaid
flowchart LR
subgraph client
    aac["auth account connection"] -->|1: client sends request| request
    response-decrypt -->|21. parse and store application jwt| ajwt["application account jwt"]
    ajwt -->|22. connect to application nats account| appac["application account connection"]
end
subgraph naa["NATS: AUTH account"]
request -->|2: auth register service recieves it| auth.register
auth.reponse.inbox["auth.response.{inbox}"]
    subgraph validation
        request-parse -->|4: read header and data| headers & data
        headers -->|5: store reply header for later| reply-inbox
        data -->|6: decrypt data payload| decrypt
        decrypt -->|7: store decrypted data| payload
        payload -->|8: read back public key and signature| public-key & signature
        subgraph parse
            public-key -->|9a: call validate with public key| validate-signature
            signature -->|9b: call validate with signature| validate-signature
            validate-signature -->|10a: validated signature| valid
            validate-signature -->|10b: invalid signature| invalid
            valid -->|11a: continue parsing data| parse-data
            parse-data -->|12a: read back values| client-uuid & role-token & metadata
            client-uuid & role-token & metadata -->|13a: lookup roles based on values for permission merging| match-roles
            match-roles -->|14a: generate response jwt| generate-jwt
            genrate-jwt -->|15a: store jwt| jwt-kv
            generate-jwt -->|15b: insert jwt to response payload| response-payload
            invalid -->|11b: generate error response| response-payload
        end
        response-payload -->|16: encrypt with public key| encrypt
        encrypt -->|17. insert encrypted payload into response| response
        reply-inbox -->|18. insert reply inbox into response| response
    end
end
subgraph nappa["NATS: Application Account"]
    services
    kvs
    streams
end
response -->|19: send response to inbox| auth.reponse.inbox["auth.response.{inbox}"]
auth.register -->|3: begin parsing| request-parse
appac -->|23. user application account resources| services & kvs & streams
response-decrypt -->|20: read response and begin decrypting| auth.reponse.inbox
```
## renew client
## unregister client
## refresh client
## pending clients
## registered clients
## unregistered clients
## update client

# roles concept
Role based access control has a root in providing least privelge for reoccuring needs, for users or services this makes sense.
The roles concept implements a templare for client permissions to allow them to be securely provisioned and issued at registration or on refresh of client credentials.
# service subject endpoints
## entities interacting with endpoints
This table displays the expected entities that will interact with each service and how.
| entity | purpose |
|--------|---------|
| client | client requesting registration services |
| auth server | authenticaiton server providing client registration services |
| provisioner | programatic access to support client deployment and configuration |
| admin | user or programatic user performing adminsitrative functions againist auth server |

## endpoints
This table describes the listening subjects registered in nats, who is subscribing to them, and who is publsihing to them in order to show case the flow of data within the service.
| subject | purpose | subscriber | Publisher |
|---------|---------|------------|-----------|
| auth.client.create | a request to generate a user credential with or without a supplied public key | admin |
| auth.client.read.{client-id} | read client record | auth server | admin |
| auth.client.update | update client configuration | auth server | admin |
| auth.client.delete | delete client configuration | auth server | admin |
| auth.client.register | client requests to be issued credential | auth server | client |
| auth.client.renew | client request to renew expired credential | auth server | client |
| auth.client.unregister.{client-id} | client request to unregister and revoke crednetials | auth server | client |
| auth.client.refresh.{client-id} | refresh jwt client subscription, force renew and reconnect | client | auth server |
| auth.client.approve.{client-id} | approves client request | admin |
| auth.client.reject.{cliend-id} | rejects client request | admin |
| auth.client.list | list all client records | auth server | admin |
| auth.client.list.pending | list pending clients | auth server | admin |
| auth.client.list.registered | list registered / approved clients | auth server | admin |
| auth.client.list.unregistered | list unregistered clients | auth server | admin |
| auth.approvals.rule.list | lists current rules configured in the system | admin |
| auth.approvals.rule.create | creates new approval rule for processing requests | admin |
| auth.approvals.rule.update | updates approval rule with new configuration | admin |
| auth.approvals.rule.read.{rule-id} | read approval rule configuration | admin |
| auth.approvals.rule.delete.{rule-id} | delete approval rule | admin |
| auth.approvals.alerts.list | lists alerts for attempted approvals | admin |
| auth.approvals.approved.list | lists approved requests by client id | admin |
| auth.approvals.approved.read.{client-id} | reads client approval records, showing matching rule and assigned jwt | admin |
| auth.approvals.rejected.list | lists rejected requests by client id | admin |
| auth.approvals.rejected.read.{client-id} | reads client rejection record, showing rejection reason | admin |
| auth.role.token.read.{role-id} | read latest role token id | auth server | provisioner |
| auth.role.token.renew.{role-id} | forces role id token to rotate | auth servie | admin |
| auth.role.create | creates new role from provided request configuration | auth service | admin |
| auth.role.diable.{role-id} | disables role related requests | auth service | admin |
| auth.role.delete.{role-id} | deletes role and related data | auth service | admin |
| auth.role.update.{role-id} | update role configuration | auth service | admin |
| auth.role.read.{role-id} | read role configuration | auth service | admin |
| auth.role.list | list the roles in the system by id | auth service | admin |

## supported workflows
1. auth server workflow
    * customer uses tooling and known provisioners to interact with auth server to acquire role tokens used in client registration
    * customer configures approval rules for roles, metadata, and other factors to assign permissions
    * customer manages and implements roles for services and user types that allocate desired permissions
2. custom service workflow
    * customer uses api to create clients or issue client jwts
    * customer can still leverage automated renew functions in client
    * customer does not use approval rules
    * customer can choose to use roles if they desire but permissions can be set directly on the client record

# work in Progress

# request and response payloads

## auth.client.register
Request:
* uuid
* public key
* data signature
* metadata
    * name: string
    * architecture: string
    * region: string
    * cluster: string
    * runtime: string
    * hardware-uuid: uuid
    * tags: map[string]any

Response:
* jwt: string (base64 encoded jwt)

## auth.renew.{client uuid}
