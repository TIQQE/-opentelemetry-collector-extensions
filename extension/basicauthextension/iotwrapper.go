package basicauthextension

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/aws/aws-sdk-go/service/iot"
	"github.com/pkg/errors"
	"os"
	"strings"
)

var (
	IOTclient *iot.IoT
)

func initIOTClient() {
	if IOTclient != nil {
		return
	}

	s := GetSession()
	IOTclient = iot.New(s)
}

func ListThingPrincipals(thingName string) (string, error) {
	initIOTClient()
	b := iot.ListThingPrincipalsInput{ThingName: &thingName}

	test, err := IOTclient.ListThingPrincipals(&b)
	if err != nil {
		return "", errors.Wrap(err, "Unable to ListThingPrincipals")
	}
	println("ListThingPrincipals success")
	return strings.Split(*test.Principals[0], "/")[1], nil
}

func DescribeCertificate(certificateId string, thingName string) ([]byte, error) {
	initIOTClient()
	b := iot.DescribeCertificateInput{CertificateId: &certificateId}

	test, err := IOTclient.DescribeCertificate(&b)
	if err != nil {
		return []byte(""), errors.Wrap(err, "Unable to DescribeCertificate")
	}
	println("DescribeCertificate success")
	println(*test.CertificateDescription.CertificatePem)
	err = os.WriteFile(thingName, []byte(*test.CertificateDescription.CertificatePem), 0644)
	if err != nil {
		return []byte(""), errors.Wrap(err, "Unable to WriteFile")
	}
	return []byte(*test.CertificateDescription.CertificatePem), nil
}

func GetCertificateByThingName(thingName string) ([]byte, error) {
	cert, err := os.ReadFile(thingName)
	if err != nil {
		key, err := ListThingPrincipals(thingName)
		if err != nil {
			return []byte(""), errors.Wrap(err, "Unable to GetCertificateByThingName")
		}
		certNew, err := DescribeCertificate(key, thingName)
		if err != nil {
			return []byte(""), errors.Wrap(err, "Unable to GetCertificateByThingName")
		}
		println("GetCertificateByThingName certNew success")
		return certNew, nil
	}
	println("GetCertificateByThingName cert success")
	return cert, nil
}

func VerifyClient(thingName string, message string, signature string) bool {

	publicKey, err := getPublicKeyByThingName(thingName)
	if err != nil {
		panic(err)
	}
	msg := []byte(message)

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		panic(err)
	}
	msgHashSum := msgHash.Sum(nil)

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, []byte(signature), nil)
	if err != nil {
		fmt.Println("could not verify signature: ", err)
		return false
	}
	fmt.Println("signature verified")
	return true
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is vali
}

func getPublicKeyByThingName(thingName string) (*rsa.PublicKey, error) {
	certificate, err := GetCertificateByThingName(thingName)
	if err != nil {
		errors.Wrap(err, "Unable to getPublicKeyByThingName")
	}
	block, _ := pem.Decode(certificate)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsaPublicKey, nil
}
