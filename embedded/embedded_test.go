package embedded_test

import (
	"crypto/rand"
	"testing"

	"filippo.io/age/embedded"
)

const fileKeySize = 16

func TestNewRecipient(t *testing.T) {
	_, err := embedded.NewRecipient("age1yubiembed1qtyc0zuw8xced8zzn9rjmvsc0dejerp0aw9yxe8ws7welfk90wkpvhgjhyr")
	if err != nil {
		t.Fatal(err)
	}
}

func TestWrapFileKey(t *testing.T) {
	fileKey := make([]byte, fileKeySize)
	if _, err := rand.Read(fileKey); err != nil {
		t.Fatal(err)
	}

	id, err := embedded.NewRecipient("age1yubiembed1qtyc0zuw8xced8zzn9rjmvsc0dejerp0aw9yxe8ws7welfk90wkpvhgjhyr")
	if err != nil {
		t.Fatal(err)
	}
	s, err := id.Wrap(fileKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range s {
		if v.Type != "piv-p256" {
			t.Fatal("bad stanza type")
		}
	}
}
