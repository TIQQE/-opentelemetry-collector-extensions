package basicauthextension

import (
	"context"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3iface"
	"github.com/aws/aws-xray-sdk-go/xray"
	"github.com/pkg/errors"
	"github.com/tiqqe/go-logger"
	"io/ioutil"
)

var (
	S3Client s3iface.S3API
)

func initS3Client() {
	if S3Client != nil {
		return
	}

	s := GetSession()
	svc := s3.New(s)
	xray.AWS(svc.Client)
	S3Client = svc
}

func S3Get(ctx context.Context, bucket, key string) ([]byte, error) {
	logger.InfoStringf("Fetching file %s from bucket %s", key, bucket)
	initS3Client()

	input := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}

	result, err := S3Client.GetObjectWithContext(ctx, input)
	if err != nil {
		return nil, errors.Wrap(err, "s3 GET failed")
	}

	defer result.Body.Close()
	data, err := ioutil.ReadAll(result.Body)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read s3 get body")
	}

	return data, nil
}
