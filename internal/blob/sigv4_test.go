package blob

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Worked examples from the AWS S3 documentation ("Signature Calculations
// for the Authorization Header: Transferring Payload in a Single Chunk").
var awsExampleCreds = Credentials{
	AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
	SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}

var awsExampleTime = time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)

func TestSigV4AWSExampleGetObject(t *testing.T) {
	req, err := http.NewRequest("GET", "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	require.NoError(t, err)
	req.Header.Set("Range", "bytes=0-9")
	signV4(req, awsExampleCreds, "us-east-1", awsExampleTime, emptySHA256)

	require.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"+
		"SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"+
		"Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41",
		req.Header.Get("Authorization"))
	require.Equal(t, "20130524T000000Z", req.Header.Get("X-Amz-Date"))
}

func TestSigV4AWSExamplePutObject(t *testing.T) {
	req, err := http.NewRequest("PUT", "https://examplebucket.s3.amazonaws.com/test$file.text", nil)
	require.NoError(t, err)
	req.Header.Set("Date", "Fri, 24 May 2013 00:00:00 GMT")
	req.Header.Set("X-Amz-Storage-Class", "REDUCED_REDUNDANCY")
	signV4(req, awsExampleCreds, "us-east-1", awsExampleTime,
		"44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072") // sha256("Welcome to Amazon S3.")

	require.Equal(t, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"+
		"SignedHeaders=date;host;x-amz-content-sha256;x-amz-date;x-amz-storage-class,"+
		"Signature=98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd",
		req.Header.Get("Authorization"))
}

func TestSigV4SessionTokenIsSigned(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://b.s3.amazonaws.com/k", nil)
	creds := awsExampleCreds
	creds.SessionToken = "session"
	signV4(req, creds, "us-east-1", awsExampleTime, emptySHA256)
	require.Equal(t, "session", req.Header.Get("X-Amz-Security-Token"))
	require.Contains(t, req.Header.Get("Authorization"), "x-amz-security-token")
}

func TestURIEncode(t *testing.T) {
	require.Equal(t, "/a/b%20c/%24%2B~_-.", uriEncodePath("/a/b c/$+~_-."))
}
