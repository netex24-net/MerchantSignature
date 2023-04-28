// draft 
package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const nonce = 1

const privateKeyPemEncoded = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIGPx9k+3YaWR********************************************
****************************************************************
************************************
-----END EC PRIVATE KEY-----`

const publicKeyPemEncoded = `-----BEGIN PUBLIC KEY-----
****************************************************************
****************************************************************
****************************************************************
********************
-----END PUBLIC KEY-----`

const merchantId = "********-****-****-****-************"

func main() {
	count := 10
	duration := time.Second * 10

	baseUrl := "https://netex24.net/api"
	url := fmt.Sprintf("%s/Merchants/%s", baseUrl, "GetBalance")

	client := &http.Client{}

	for i := 0; i < count; i++ {
		// nonce as C# Ticks
		now := time.Now()
		_, offset := now.Zone()
		nonce := fmt.Sprintf("%d", (now.UnixNano()+int64(offset*1000000000))/100+unixTimeTicks)

		// "R and S sequence" sign
		signature, err := ecdsaSignature("", merchantId, nonce, privateKeyPemEncoded)
		if err != nil {
			panic(err)
		}

		var req *http.Request
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			panic(err)
		}
		req.Header["ECDSA"] = []string{signature}
		doRequest(client, req, i)
		time.Sleep(duration)
	}
}

func doRequest(client *http.Client, req *http.Request, i int) {
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	balance := Balance{}

	body, _ := ioutil.ReadAll(resp.Body)

	result := true
	if err = json.Unmarshal(body, &balance); err != nil {
		result = false
	}

	fmt.Printf("%d: %v: %s\n", i, result, time.Now().UTC())
}

// sequence of bytes, but as a pair of values (𝑟,𝑠)
func ecdsaSignature(request, id, nonce, privateKeyPemEncoded string) (string, error) {
	var err error
	var privateKey *ecdsa.PrivateKey
	if privateKey, err = DecodeEcdsaPrivateKeyPemEncoded(privateKeyPemEncoded); err != nil {
		return "", err
	}
	signatureRawData := strings.ToLower(fmt.Sprintf("%s%s%s", request, id, nonce))
	var signature EcdsaSignature
	if signature, err = EcdsaSign(signatureRawData, privateKey); err != nil {
		return "", err
	}
	r := signature.R.Bytes()
	s := signature.S.Bytes()
	// prepend extra bytes if keys have different length
	rLen := len(r)
	sLen := len(s)
	lenDiff := rLen - sLen
	if lenDiff != 0 {
		abs := int(math.Abs(float64(lenDiff)))
		if lenDiff < 0 {
			r = fitKeyLen(r, 0x00, abs)
		} else {
			s = fitKeyLen(s, 0x00, abs)
		}
	}
	return fmt.Sprintf("%X%X:%s:%s", r, s, id, nonce), nil
}

func fitKeyLen(key []byte, prefix byte, numberOfPrefixBytes int) []byte {
	for i := 0; i < numberOfPrefixBytes; i++ {
		key = append([]byte{prefix}, key...)
	}
	return key
}

func EcdsaSign(stringToSign string, privateKey *ecdsa.PrivateKey) (EcdsaSignature, error) {
	hash := sha512.Sum512([]byte(stringToSign))
	r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
	signature := EcdsaSignature{}
	if err != nil {
		return signature, err
	}
	signature.R = *r
	signature.S = *s
	return signature, nil
}

type EcdsaSignature struct {
	R big.Int
	S big.Int
}

func DecodeEcdsaPrivateKeyPemEncoded(pemEncodedPrivateKey string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemEncodedPrivateKey))
	x509Encoded := block.Bytes
	privateKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

type Balance struct {
	Balances []struct {
		CurrencyId    int     `json:"currencyId"`
		Balance       float64 `json:"balance"`
		HoldAmount    float64 `json:"holdAmount"`
		PendingAmount float64 `json:"pendingAmount"`
	} `json:"balances"`
}
