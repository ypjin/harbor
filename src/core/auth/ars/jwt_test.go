package ars

import (
	"fmt"
	"testing"

	"github.com/dgrijalva/jwt-go"
	"github.com/goharbor/harbor/src/common/utils/log"
)

var (
	tokenString = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1ODgyMzcxMTksImlhdCI6MTU4NTY0NTExOSwiaXNzIjoiaGFyYm9yLXRva2VuLWRlZmF1bHRJc3N1ZXIiLCJpZCI6MSwicGlkIjoyLCJhY2Nlc3MiOlt7IlJlc291cmNlIjoiL3Byb2plY3QvMi9yZXBvc2l0b3J5IiwiQWN0aW9uIjoicHVzaCIsIkVmZmVjdCI6IiJ9LHsiUmVzb3VyY2UiOiIvcHJvamVjdC8yL2hlbG0tY2hhcnQiLCJBY3Rpb24iOiJyZWFkIiwiRWZmZWN0IjoiIn0seyJSZXNvdXJjZSI6Ii9wcm9qZWN0LzIvaGVsbS1jaGFydC12ZXJzaW9uIiwiQWN0aW9uIjoiY3JlYXRlIiwiRWZmZWN0IjoiIn1dfQ.CAmcnNIRdEy1uuH5Vbcbal9lOkUMyNWTnHUcd8Br3ke8I_xUyo4AvXQ8NHRiMFFlvzFmIbxyha8X_zMTaLslFQwTli4mLm6-KfUJYUW5NmW1ogsxam2aG2sMJD0ToYU8ja_y-NrMOQIt-MjtenKasKwqw3jVs_qKerSNWOHZsoXxIA7K-dI4xsmBJiHqoCNKWTCGUfR_etTJ_kCOC1Lv88CLNVqGMS43-8I6qAqp3W0hkDrATVbIwe6kl-Vg6eqAOpZWDX3hM05uJPQ5gW4xjFGBkDTMe5PsIy_aNKwQoNNZ_FK0ZMc5_C21v7VOLPu8ndzFagWFUGMXHlybM3aSbko7BQb7CwzhQLbsawSA9VsGcLKD0SUG7Mo2mlcaPtG_0nRZrKTd1awhOjf4kL3Bv31acavp_qGGRKJbQ4TQanLxT1-ESaJNoxrUSt_rt-TFwO5bE1CHsUnl-UvtCSyJMv1plbl_NrZsxkRlV4rCtmISthR_BMAtUX94iKHsY8nWlI88lPvWuLwZUza190PzlvZAep1ssNQYLw-J6-jCrQsUX4HB7804r6IvCSOlAgOzkgpjHoG5ih05EVXT_x3mUaI5AbQt_IaeDhErh6-SCc-_-jjCkrn5BlFkmR3DxpFQLkCbwkI8JqSRpSa6Hug4jty2QyMQAMlq5vQ8_pRJfDA"
	// tokenString = "abcdakdg;ag"
)

func TestParseJWT(t *testing.T) {

	claims := jwt.MapClaims{}
	token, parts, err := new(jwt.Parser).ParseUnverified(tokenString, claims)

	// https://github.com/dgrijalva/jwt-go
	// https://godoc.org/github.com/dgrijalva/jwt-go#ParseWithClaims
	// https://stackoverflow.com/questions/45405626/decoding-jwt-token-in-golang
	// jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
	// 	return []byte("<YOUR VERIFICATION KEY>"), nil
	// })

	if err != nil {
		t.Errorf("%v", err)
		return
	}

	log.Infof("token: %+v", token)
	log.Infof("parts: %+v", parts)

	// do something with decoded claims
	for key, val := range claims {
		fmt.Printf("Key: %v, value: %v\n", key, val)
	}
}
