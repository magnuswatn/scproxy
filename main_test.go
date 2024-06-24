package main

import (
	"encoding/hex"
	"slices"
	"testing"
	"time"
)

var pinData = []struct {
	ref     int64
	key     string
	inApdu  string
	outApdu string
}{
	{1119781658, "4F4EAAADF30F7B5220FF31743617EBFC", "FFFF010442BE831A0504A0200082088A73E8CFFFFFFFFF", "a02000820836323930ffffffff"},
	{944398877, "0ba339dd5b602f8beda55f25a8cf4d6e", "FFFF0104384A621D0504A02000820866F12F66FFFFFFFF", "a02000820836323930ffffffff"},
}

func TestDeObscurifyPinApdu(t *testing.T) {

	for _, pd := range pinData {
		key, _ := hex.DecodeString(pd.key)
		inApdu, _ := hex.DecodeString(pd.inApdu)
		outApdu, _ := hex.DecodeString(pd.outApdu)

		var knownKeys = make(map[int64]refKey)
		knownKeys[pd.ref] = refKey{key: key, createdAt: time.Now()}

		deObscurifiedApdu, e := deObscurifyPinApdu(inApdu, knownKeys)
		if e != nil {
			t.Fatalf("error: %s\n", e)
		}
		if !slices.Equal(deObscurifiedApdu, outApdu) {
			t.Errorf("expected: %s got: %s\n", hex.EncodeToString(outApdu), hex.EncodeToString(deObscurifiedApdu))
		}
	}
}
