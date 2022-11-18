package basicauthextension

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/pkg/errors"
)

var sess *session.Session
var region string

func GetSession() *session.Session {
	if sess != nil {
		return sess
	}

	c, err := getHttpClient()
	if err != nil {
		panic(err)
	}

	s, err := session.NewSession(&aws.Config{
		HTTPClient: c,
	})
	if err != nil {
		panic(errors.Wrap(err, "failed to create aws session"))
	}

	sess = s

	region = *sess.Config.Region
	if region == "" {
		sess.Config.Region = setRegion()
	}
	return sess
}

func setRegion() *string {
	return aws.String("eu-north-1")
}
