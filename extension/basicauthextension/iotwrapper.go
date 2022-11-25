package basicauthextension

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/TIQQE/opentelemetry-collector-extensions/extension/basicauthextension/utility"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/tiqqe/go-logger"
	"os"
	"strings"
)

var (
	IOTclient *iot.Client
)

func initIOTClient() {
	if IOTclient != nil {
		return
	}

	cfg, _ := config.LoadDefaultConfig(context.TODO(),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(os.Getenv("IOT_AWS_ACCESS_KEY_ID"), os.Getenv("IOT_AWS_SECRET_ACCESS_KEY"), "")),
	)
	IOTclient = iot.NewFromConfig(cfg)
}

func ListThingPrincipals(thingName string) (string, error) {
	initIOTClient()
	b := iot.ListThingPrincipalsInput{ThingName: &thingName}

	test, err := IOTclient.ListThingPrincipals(context.TODO(), &b)
	if err != nil {
		utility.LogError(err, "DescribeCertificate", "failed to ListThingPrincipals")
		return "", err
	}
	logger.InfoString("ListThingPrincipals success")
	return strings.Split(test.Principals[0], "/")[1], nil
}

func DescribeCertificate(certificateId string, thingName string) ([]byte, error) {
	initIOTClient()
	b := iot.DescribeCertificateInput{CertificateId: &certificateId}

	test, err := IOTclient.DescribeCertificate(context.TODO(), &b)
	if err != nil {
		utility.LogError(err, "DescribeCertificate", "failed to IOTclient.DescribeCertificate")
		return nil, err
	}
	err = os.WriteFile(thingName, []byte(*test.CertificateDescription.CertificatePem), 0644)
	if err != nil {
		utility.LogError(err, "DescribeCertificate", "failed to os.WriteFile")
		return nil, err
	}
	logger.InfoString("DescribeCertificate success")
	logger.InfoString(*test.CertificateDescription.CertificatePem)
	return []byte(*test.CertificateDescription.CertificatePem), nil
}

func GetCertificateByThingName(thingName string) ([]byte, error) {
	cert, err := os.ReadFile(thingName)
	if err != nil {
		key, err := ListThingPrincipals(thingName)
		if err != nil {
			utility.LogError(err, "GetCertificateByThingName", "failed to ListThingPrincipals")
			return nil, err
		}
		certNew, err := DescribeCertificate(key, thingName)
		if err != nil {
			utility.LogError(err, "GetCertificateByThingName", "failed to DescribeCertificate")
			return nil, err
		}
		logger.InfoString("GetCertificateByThingName certNew success")
		return certNew, nil
	}
	logger.InfoString("GetCertificateByThingName cert success")
	return cert, nil
}

func VerifyClient(thingName string, message string, signature string) bool {

	publicKey, err := getPublicKeyByThingName(thingName)
	if err != nil {
		utility.LogError(err, "VerifyClient", "failed to verify signature - getPublicKeyByThingName")
		return false
	}
	msg := []byte(message)

	// Before signing, we need to hash our message
	// The hash is what we actually sign
	msgHash := sha256.New()
	_, err = msgHash.Write(msg)
	if err != nil {
		utility.LogError(err, "VerifyClient", "failed to verify signature - msgHash.Write")
		return false
	}
	msgHashSum := msgHash.Sum(nil)

	// To verify the signature, we provide the public key, the hashing algorithm
	// the hash sum of our message and the signature we generated previously
	// there is an optional "options" parameter which can omit for now
	sig, _ := hex.DecodeString(signature)
	err = rsa.VerifyPSS(publicKey, crypto.SHA256, msgHashSum, sig, nil)
	if err != nil {
		utility.LogError(err, "VerifyClient", "failed to verify signature - VerifyPSS")
		return false
	}
	logger.InfoString("Success to verify signature")
	return true
	// If we don't get any error from the `VerifyPSS` method, that means our
	// signature is vali
}

func getPublicKeyByThingName(thingName string) (*rsa.PublicKey, error) {
	certificate, err := GetCertificateByThingName(thingName)
	if err != nil {
		utility.LogError(err, "getPublicKeyByThingName", "failed to GetCertificateByThingName")
		return nil, err
	}
	block, _ := pem.Decode(certificate)
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	return rsaPublicKey, nil
}
