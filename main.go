// A secure NATS-based registration flow using NKeys and JWT encryption utilities.
// Includes: micro integration and JWT push to resolver for new users.
// Requires:
// - github.com/nats-io/nats.go
// - github.com/nats-io/nkeys
// - github.com/nats-io/jwt/v2
// - github.com/nats-io/micro
// initial generated code examples to get started with, nothing production ready and untested at this time.

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/micro"
	nats "github.com/nats-io/nats.go"
	nkeys "github.com/nats-io/nkeys"
)

// ------------------------
// Shared types and helpers
// ------------------------
type RegistrationRequest struct {
	ClientPubKey string `json:"client_pub"`
	Payload      []byte `json:"payload"`
}

type RegistrationResponse struct {
	Encrypted []byte `json:"encrypted"`
}

func mustGenerateNKeyPair() (nkeys.KeyPair, string) {
	kp, err := nkeys.CreateUser()
	if err != nil {
		log.Fatalf("failed to generate NKey: %v", err)
	}
	pub, _ := kp.PublicKey()
	return kp, pub
}

// ----------------
// Auth Microservice
// ----------------
func startAuthService(nc *nats.Conn, serverKP nkeys.KeyPair, operatorKP nkeys.KeyPair) {
	serverPub, _ := serverKP.PublicKey()

	svc := micro.NewService(nc, micro.Config{Name: "auth.register"})

	svc.AddEndpoint("", func(req micro.Request) {
		var regReq RegistrationRequest
		if err := json.Unmarshal(req.Data(), &regReq); err != nil {
			log.Println("Invalid request payload:", err)
			return
		}

		clientKP, err := nkeys.FromPublicKey(regReq.ClientPubKey)
		if err != nil {
			log.Println("Invalid client pubkey:", err)
			return
		}

		// Decrypt registration data
		msg, err := jwt.Decrypt(serverKP, clientKP, regReq.Payload)
		if err != nil {
			log.Println("Failed to decrypt registration payload:", err)
			return
		}
		log.Printf("Decrypted registration data: %s", string(msg))

		// Mint a new user JWT for the "communication" account
		commAccKP, _ := nkeys.FromSeed([]byte(os.Getenv("COMM_ACC_SEED")))
		accPub, _ := commAccKP.PublicKey()
		now := time.Now()
		userClaim := jwt.NewUserClaims(regReq.ClientPubKey)
		userClaim.Issuer = accPub
		userClaim.Name = fmt.Sprintf("client-%d", now.UnixNano())
		userClaim.Tags = []string{"registered"}
		userClaim.Limits.Src = jwt.Limits{
			Subs: -1,
			Data: -1,
			Payload: -1,
		}

		userJWT, err := userClaim.Encode(commAccKP)
		if err != nil {
			log.Println("Error encoding JWT:", err)
			return
		}

		// Push JWT to resolver
		operatorPub, _ := operatorKP.PublicKey()
		if err := jwt.Publish(&jwt.PublishOptions{
			JWT:        userJWT,
			ClaimsID:   regReq.ClientPubKey,
			IssuerKey:  operatorKP,
			NATSClient: nc,
		}); err != nil {
			log.Println("Failed to push JWT to resolver:", err)
			return
		}

		// Encrypt response
		encResp, err := jwt.Encrypt(clientKP, serverKP, []byte(userJWT))
		if err != nil {
			log.Println("Encryption failed:", err)
			return
		}

		resp := RegistrationResponse{Encrypted: encResp}
		respBytes, _ := json.Marshal(resp)
		req.Respond(respBytes)
	})

	// Public key responder
	nc.Subscribe("auth.pubkey", func(m *nats.Msg) {
		m.Respond([]byte(serverPub))
	})

	log.Println("Auth microservice running with public key:", serverPub)
	svc.Run()
}

// --------------
// Client Logic
// --------------
func clientRegister(nc *nats.Conn, clientKP nkeys.KeyPair) {
	clientPub, _ := clientKP.PublicKey()

	msg, err := nc.Request("auth.pubkey", nil, time.Second)
	if err != nil {
		log.Fatalf("Failed to get server pubkey: %v", err)
	}
	serverPubRaw := msg.Data
	serverKP, _ := nkeys.FromPublicKey(string(serverPubRaw))

	payload := []byte("my_secret_registration_data")
	encrypted, err := jwt.Encrypt(serverKP, clientKP, payload)
	if err != nil {
		log.Fatalf("Encryption failed: %v", err)
	}

	req := RegistrationRequest{
		ClientPubKey: clientPub,
		Payload:      encrypted,
	}
	reqBytes, _ := json.Marshal(req)

	sub, _ := nc.SubscribeSync(nats.NewInbox())
	nc.PublishRequest("auth.register", sub.Subject, reqBytes)

	respMsg, err := sub.NextMsg(2 * time.Second)
	if err != nil {
		log.Fatalf("No response: %v", err)
	}

	var regResp RegistrationResponse
	json.Unmarshal(respMsg.Data, &regResp)

	decrypted, err := jwt.Decrypt(clientKP, serverKP, regResp.Encrypted)
	if err != nil {
		log.Fatalf("Decryption failed: %v", err)
	}
	log.Printf("Client received JWT: %s", string(decrypted))
}

// ----------------
// Main Entrypoint
// ----------------
func main() {
	nc, _ := nats.Connect(nats.DefaultURL)
	defer nc.Drain()

	serverKP, _ := nkeys.CreateServer()
	operatorKP, _ := nkeys.FromSeed([]byte(os.Getenv("OPERATOR_SEED")))

	go startAuthService(nc, serverKP, operatorKP)

	time.Sleep(1 * time.Second)

	clientKP, _ := nkeys.CreateUser()
	clientRegister(nc, clientKP)
}

/*
JWT Configuration Notes:
- Shared account: `auth`
- Permissions for the shared user (in the auth account):

{
  "permissions": {
    "pub": {
      "allow": ["auth.register"]
    },
    "sub": {
      "allow": ["_INBOX.>", "auth.pubkey"]
    }
  }
}

- The generated user is added to account: `communication`
- Server uses operator credentials to push user JWT to NATS resolver
- Set environment variables:
  - OPERATOR_SEED (operator key for JWT signing/publishing)
  - COMM_ACC_SEED (communication account key)
*/
