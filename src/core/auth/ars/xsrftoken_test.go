package ars

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/goharbor/harbor/src/common/utils/log"
)

var (
	Secret = "HRK6vedlDgvFp0sQw7Hf8QXKhmmeco8kfp6OL5ut"
)

func TestDecode(t *testing.T) {

	val := "WW9XNHVwZVh6cTN3WUF4MVFMWGJjUE9KcjdsVmFjenA=|1585648643814787707|12b1b26340a449c8f222cc59645c704f273ec2cef4e4143d5dfe147cadb7febd"

	parts := strings.SplitN(val, "|", 3)

	if len(parts) != 3 {
		t.Errorf("The encoded xsrf token should have 3 parts")
		return
	}

	vs := parts[0]
	timestamp := parts[1]
	sig := parts[2]

	h := hmac.New(sha256.New, []byte(Secret))
	fmt.Fprintf(h, "%s%s", vs, timestamp)

	if fmt.Sprintf("%02x", h.Sum(nil)) != sig {
		t.Errorf("sig mismatch")
	}

	res, _ := base64.URLEncoding.DecodeString(vs)
	log.Infof("decoded xsrf token: %s", res)
}
