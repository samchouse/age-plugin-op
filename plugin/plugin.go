package plugin

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"filippo.io/age/plugin"
)

const (
	Name = "op"
)

// CreateIdentity creates a new identity.
// Returns the identity and the corresponding recipient.
func CreateIdentity(privateKeyPath string) (*OpIdentity, error) {
	_, err := ReadKeyOp(privateKeyPath, "")
	if err != nil {
		return nil, err
	}

	identity, err := NewOpIdentity(privateKeyPath, "")
	if err != nil {
		return nil, err
	}

	return identity, nil
}

func DecodeIdentity(s string) (*OpIdentity, error) {
	var key OpIdentity
	name, b, err := plugin.ParseIdentity(s)
	if err != nil {
		return nil, err
	}
	if name != Name {
		return nil, fmt.Errorf("invalid hrp")
	}
	r := bytes.NewBuffer(b)
	for _, f := range key.serialize() {
		if err := binary.Read(r, binary.BigEndian, f); err != nil {
			return nil, err
		}
	}

	splits := strings.Split(strings.TrimPrefix(string(b), "\x01"), "==")
	if len(splits) != 2 {
		return nil, fmt.Errorf("failed to decode recipient data: missing parts")
	}

	key.user = splits[0]
	key.privateKeyPath = splits[1]

	return &key, nil
}
