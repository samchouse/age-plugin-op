package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"filippo.io/age"
	"filippo.io/age/plugin"
	"fmt"
)

type OpRecipient struct {
	privateKeyPath string
	tag            []byte
}

var _ age.Recipient = &OpRecipient{}

// Tag returns the 4 first bytes of the path to the key
// this is used to find the correct identity in a stanza
func (r *OpRecipient) Tag() []byte {
	return r.tag
}

func (r *OpRecipient) String() string {
	return EncodeRecipient(r)
}

func NewRecipient(opPath string) *OpRecipient {
	sum := sha256.Sum256([]byte(opPath))
	return &OpRecipient{
		privateKeyPath: opPath,
		tag:            sum[:4],
	}
}

func (r *OpRecipient) Wrap(fileKey []byte) ([]*age.Stanza, error) {
	//TODO implement me
	panic("implement me")
}

func EncodeRecipient(r *OpRecipient) string {
	var b bytes.Buffer
	err := binary.Write(&b, binary.BigEndian, []byte(r.privateKeyPath))
	if err != nil {
		Log.Println("failed to encode recipient: %v", err)
	}
	return plugin.EncodeRecipient(Name, b.Bytes())
}

func DecodeRecipient(s string) (*OpRecipient, error) {
	name, b, err := plugin.ParseRecipient(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode recipient: %v", err)
	}
	if name != Name {
		return nil, fmt.Errorf("invalid plugin for type %s", name)
	}

	return NewRecipient(string(b)), nil
}
