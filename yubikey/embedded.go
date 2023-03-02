// Copyright 2023 Pedro Vilaça (reverser@put.as). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.
//
// some code/ideas copied from yubage by Tommi Virtanen
// https://github.com/tv42/yubage
// Copyright (c) 2021 Tommi Virtanen

// Implements yubikey based encryption without calling an external plugin
package embedded

import (
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	age "github.com/gdbinit/yage"
	"github.com/gdbinit/yage/internal/bech32"
	"github.com/go-piv/piv-go/piv"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

const (
	// follows age-plugin-yubikey label, which is != from yubage
	// this should be domain/piv-p256
	wrapLabel        = "piv-p256"
	IDENTITY_PREFIX  = "AGE-PLUGIN-YUBIEMBED-"
	RECIPIENT_PREFIX = "age1yubiembed"
)

type EmbeddedRecipient struct {
	name     string
	encoding string
	// these are the parameters extracted from the recipient string
	compressed []byte
	public     *ecdh.PublicKey
	tag        string // follows age-plugin-yubikey tag definition, which is != from yubage
}

var _ age.Recipient = &EmbeddedRecipient{}

// NewRecipient returns a new EmbeddedRecipient instance
// includes the data extracted from the recipient string
// necessary to wrap (encrypt) the encryption file key
func NewRecipient(s string) (*EmbeddedRecipient, error) {
	hrp, compressed, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient encoding %q: %v", s, err)
	}
	if !strings.HasPrefix(hrp, "age1") {
		return nil, fmt.Errorf("not a plugin recipient %q: %v", s, err)
	}
	name := strings.TrimPrefix(hrp, "age1")

	// extract and convert to new ecdh.PublicKey
	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, compressed)
	if x == nil {
		return nil, errors.New("does not contain a compressed P-256 key")
	}
	p := &ecdsa.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}
	// finally convert ecdsa.PublicKey to ecdh.PublicKey
	pub, err := p.ECDH()
	if err != nil {
		return nil, fmt.Errorf("ECDH public key conversion error: %v", err)
	}

	hashed := sha256.Sum256(compressed)
	tag := base64.RawStdEncoding.EncodeToString(hashed[:4])

	return &EmbeddedRecipient{
		name:       name,
		encoding:   s,
		compressed: compressed,
		public:     pub,
		tag:        tag,
	}, nil
}

// Name returns the plugin name, which is used in the recipient ("age1name1...")
// and identity ("AGE-PLUGIN-NAME-1...") encodings, as well as in the plugin
// binary name ("age-plugin-name").
func (r *EmbeddedRecipient) Name() string {
	return r.name
}

// Wrap encrypts the file key for the current recipient
// This function is called once per recipient parsed by the caller
func (r *EmbeddedRecipient) Wrap(fileKey []byte) (stanzas []*age.Stanza, err error) {
	// we have all the recipient info in our instance when initialized
	// that's the compressed recipient public key (yubikey essentially)
	// so we just need to wrap the filekey in a single stanza

	// generate the random ephemeral private key using new ecdh package
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// finally generate the secret
	// per documentation this can't return an error for the curve we are using
	sharedSecret, _ := eph.ECDH(r.public)

	// we need the compressed and base64 encoded version of the ephemeral public key
	// if we just use the bytes it will be too long and break the format spec
	// XXX: can we do this differently? I couldn't find any other way
	ephX, ephY := elliptic.Unmarshal(elliptic.P256(), eph.PublicKey().Bytes())
	ephCompressed := elliptic.MarshalCompressed(elliptic.P256(), ephX, ephY)
	ephCompressedStr := base64.RawStdEncoding.EncodeToString(ephCompressed)
	// the salt is concatenation of public keys base64 strings
	salt := make([]byte, 0, len(ephCompressed)+len(r.compressed))
	salt = append(salt, ephCompressed...)
	salt = append(salt, r.compressed...)

	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(wrapLabel))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.New(wrappingKey)
	if err != nil {
		return nil, err
	}
	// zero nonce is ok in this context per spec
	nonce := make([]byte, chacha20poly1305.NonceSize)

	// the wrapped file key that needs to be unwrapped with yubikey decryption assistance
	// without the presence of the correct yubikey this should be impossible to decrypt
	// one hopes...
	wrappedKey := aead.Seal(nil, nonce, fileKey, nil)

	// we need to tweak this to the same way the original internal/plugin/client.go processes the plugin reply
	// for "recipient-stanza" command
	stanza := &age.Stanza{
		Type: wrapLabel,
		Args: []string{r.tag, ephCompressedStr},
		Body: wrappedKey,
	}
	// the plugin can receive requests for multiple recipients
	// but we are only called once per recipient here
	stanzas = append(stanzas, stanza)
	// all done for this target recipient
	return stanzas, nil
}

type EmbeddedIdentity struct {
	name     string
	encoding string
	serial   uint32
	slot     uint8
	tag      string
	ui       *ClientUI
}

var _ age.Identity = &EmbeddedIdentity{}

type pivRecipientStanza struct {
	Index          string
	Tag            string
	EphCompressed  []byte
	WrappedFileKey []byte
}

func NewIdentity(s string) (*EmbeddedIdentity, error) {
	hrp, data, err := bech32.Decode(s)
	if err != nil {
		return nil, fmt.Errorf("invalid identity encoding: %v", err)
	}
	if !strings.HasPrefix(hrp, IDENTITY_PREFIX) || !strings.HasSuffix(hrp, "-") {
		return nil, fmt.Errorf("not a yubikey embedded plugin identity: %v", err)
	}
	// XXX: we should make this unique to avoid conflits with two yubikey
	// based identities
	name := strings.TrimSuffix(strings.TrimPrefix(hrp, "AGE-PLUGIN-"), "-")
	name = strings.ToLower(name)

	// decodes the identity
	// composed by: yubikey serial number, yubikey slot number, tag (to avoid collisions)
	if got := len(data); got != 4+1+4 {
		return nil, fmt.Errorf("wrong data length: %d", got)
	}
	tagBuf := data[5:9]
	tag := base64.RawStdEncoding.EncodeToString(tagBuf)

	return &EmbeddedIdentity{
		name:     name,
		encoding: s,
		serial:   binary.LittleEndian.Uint32(data[:4]),
		slot:     data[4],
		tag:      tag,
		ui:       pluginTerminalUI,
	}, nil
}

// Name returns the plugin name, which is used in the recipient ("age1name1...")
// and identity ("AGE-PLUGIN-NAME-1...") encodings, as well as in the plugin
// binary name ("age-plugin-name").
func (i *EmbeddedIdentity) Name() string {
	return i.name
}

func openBySerial(serial uint32) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		return nil, errors.New("no YubiKey detected")
	}
	for _, card := range cards {
		yk, err := piv.Open(card)
		if err != nil {
			continue
		}
		// we have a quite an annoying problem here
		// with Yubikeys using firmware version 4.x calling the Serial()
		// will reset the PIN cache if the policy is Once
		// this is irrelevant for Always or Never policies
		// this issue converts the Once policy into an Always
		// unless we cache the serial and open connection
		// references:
		// https://github.com/go-piv/piv-go/issues/47
		// yubikey-agent code maybeReleaseYK() @ main.go
		// with firmware version 5.x the PIN is somehow cached internally
		// and we can even open a new connection and it's still cached
		// this is more like the expected behavior from this policy
		// cache until the Yubikey is physically removed or there is a command
		// to close that "session"
		s, err := yk.Serial()
		if err != nil {
			yk.Close()
			continue
		}
		if s == serial {
			return yk, nil
		}
		yk.Close()
	}
	return nil, fmt.Errorf("Yubikey with serial %d not found", serial)
}

func (i *EmbeddedIdentity) Unwrap(stanzas []*age.Stanza) (fileKey []byte, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("%s plugin: %w", i.name, err)
		}
	}()

	// this will depend on having the right Yubikey plugged in
	// for each identity there is an associated Yubikey serial number
	// that was extracted from the identity in NewIdentity
	// if the target Yubikey isn't plugged in then we only have two options
	// we ask the user to insert it or we ask the user to skip it
	// since the user might not want (or have it) to use the requested Yubikey
	// this is the method followed by the Rust age-plugin-yubikey
	// if we do it this early we save cycles from parsing all the stanzas
	// before the right yubikey is plugged in
	// we will still need to verify that the slot certificate matches the
	// expected but that's already later on
	var yk *piv.YubiKey
	// if using Yubikeys with firmware 4.x we have a problem because PIN will always
	// be requested since we are not caching the connection (can we? how to deal with removals?)
	// this works fine for firmware 5.x since the PIN remains cached unless physically removed
	// or some other unspecified conditions (age-plugin-yubikey seems to specify a few)
	// but because we need to always find a matching plugged yubikey to be able to decrypt
	// the solution doesn't seem obvious here - just don't use Yubikeys firmware 4.x for this
	yk, err = openBySerial(i.serial)
	if err != nil {
		fmt.Println(err)
		// loop
		// XXX: we could do something better here
		// instead of trying to match the identity one by one to the corresponding yubikey
		// we can just read the plugged yubikey and find which identity corresponds to it
		// if there is none then we can try all and ask user for decisions
		// the problem is that we only receive one identity per Unwrap request
		// so we can't match this
		for {
			// XXX: for now let this stay
			// tui.go from age cmd has the right code for getting a single char
			// like we need here - the problem is importing that code into here
			// Solution is to demand an interface like age cmd does?
			// i.ui.handle("Please insert YubiKey with serial 7407429")
			msg := fmt.Sprintf("Please insert Yubikey with serial #%d", i.serial)
			choseYes, err := i.ui.Confirm("embedded", msg, "YubiKey is plugged in", "Skip this YubiKey")
			if err != nil {
				return nil, age.ErrIncorrectIdentity
			}

			if choseYes {
				yk, err = openBySerial(i.serial)
				// no error means we got the right Yubikey so we can proceed
				if err == nil {
					break
				}
			} else {
				// user selected to skip the requested Yubikey so we exit for this identity
				return nil, age.ErrIncorrectIdentity
			}
		}
	}
	// if we reach here it means there is an open yubikey connection so guarantee it will be closed
	defer yk.Close()

	var recipients []*pivRecipientStanza
	// this is where we start talking to external plugins via stdin/stdout
	// since this is embedded we include all the code here and skip all that chat
	// we just need to decrypt the filekey with the correct yubikey and send it
	// back to the caller (or an error if this wasn't possible)

	// first the plugin receives the identity and the stanzas

	// the identity was already parsed when this instance was initialized
	// so we don't need to parse anything here regarding the identity
	// other plugins prefer to do it here

	// next are the recipients stanzas
	// they contain a tag, compressed ephemeral key, and encrypted file key (by the shared key)
	for _, rs := range stanzas {
		// we should only deal with stanzas that we know how to parse
		// else per spec we should skip them
		// XXX: this uses the same type as age-plugin-yubikeys. should we change this?
		if rs.Type != wrapLabel {
			continue
		}

		tag := rs.Args[0]
		ephCompressed, err := base64.RawStdEncoding.Strict().DecodeString(rs.Args[1])
		if err != nil {
			continue
		}
		recipient := &pivRecipientStanza{
			Tag:            tag,
			EphCompressed:  ephCompressed,
			WrappedFileKey: rs.Body,
		}
		recipients = append(recipients, recipient)
	}

	// we need a reference to the slot embedded in the identity
	// which corresponds to the key used for encryption

	slot, ok := piv.RetiredKeyManagementSlot(uint32(i.slot))
	if !ok {
		// unrecognized slot
		return nil, errors.New("bad Yubikey slot")
	}

	// retrieve the certificate from the Yubikey corresponding to the target slot
	cert, err := yk.Certificate(slot)
	// if slot is empty returns an error
	if err != nil {
		return nil, errors.New("couldn't find certificate from requested slot")
	}
	// extract the public key from the certificate
	pivPubKey := cert.PublicKey.(*ecdsa.PublicKey)
	// generate a compressed version
	pivCompressed := elliptic.MarshalCompressed(pivPubKey.Curve, pivPubKey.X, pivPubKey.Y)

	// age-plugin-yubikey hashes directly the compressed bytes to generate the tag
	pivHash := sha256.Sum256(pivCompressed)
	pivTag := base64.RawStdEncoding.EncodeToString(pivHash[:4])
	// check if it's the right certificate using the tags
	if pivTag != i.tag {
		return nil, errors.New("stale tag")
	}

	// at this point we have all the recipients that we might be able to
	// work with since there might be multiple yubikeys being used
	// we need to iterate over each recipient and try to decrypt it
	for _, r := range recipients {
		// not the right recipient if the tag doesn't match - unless hash collision
		if r.Tag != i.tag {
			continue
		}
		curve := elliptic.P256()
		x, y := elliptic.UnmarshalCompressed(curve, r.EphCompressed)
		if x == nil {
			continue
		}
		ephPub := &ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		}

		// now we can extract the shared secret
		// first we need the private key instance from the yubikey
		// we need to ask user for PIN if it's not cached
		auth := piv.KeyAuth{
			PINPrompt: func() (string, error) {
				return i.ui.RequestValue("secret", "Please insert PIN:", true)
			},
		}
		// this doesn't really get a private key so no PIN is triggered here
		priv, err := yk.PrivateKey(slot, crypto.PublicKey(ephPub), auth)
		if err != nil {
			continue
		}
		// test if it's the right type
		j, ok := priv.(*piv.ECDSAPrivateKey)
		if !ok {
			continue
		}
		// now ask the yubikey for the shared key using the peer extracted from the stanza
		// this operation requires the PIN so it will be requested if PINPrompt is set
		// and session isn't cached (for Once policy)
		shared, err := j.SharedKey(ephPub)
		if err != nil {
			continue
		}

		// now we can finally unwrap (decrypt) the file key
		salt := make([]byte, 0, len(r.EphCompressed)+len(pivCompressed))
		salt = append(salt, r.EphCompressed...)
		salt = append(salt, pivCompressed...)

		ha := hkdf.New(sha256.New, shared, salt, []byte(wrapLabel))
		wrappingKey := make([]byte, chacha20poly1305.KeySize)
		if _, err := io.ReadFull(ha, wrappingKey); err != nil {
			continue
		}
		aead, err := chacha20poly1305.New(wrappingKey)
		if err != nil {
			continue
		}
		// zero nonce per spec
		nonce := make([]byte, chacha20poly1305.NonceSize)
		// decrypt all the things! bzzzzttttttt
		fileKey, err = aead.Open(nil, nonce, r.WrappedFileKey, nil)
		if err != nil {
			continue
		}
		return fileKey, nil
	}
	// our goal is to decrypt the file key and send to the caller
	// it is only possible to decrypt the key using the correct yubikey
	// we can have multiple recipients but only one yubikey will be able to
	// open the file key for that recipient
	// technically we can have more than one recipient in a single yubikey
	// since we can use other available slots to generate more keys/recipients
	return nil, age.ErrIncorrectIdentity
}

// ClientUI holds callbacks that will be invoked by (Un)Wrap if the plugin
// wishes to interact with the user. If any of them is nil or returns an error,
// failure will be reported to the plugin, but note that the error is otherwise
// discarded. Implementations are encouraged to display errors to the user
// before returning them.
type ClientUI struct {
	// DisplayMessage displays the message, which is expected to have lowercase
	// initials and no final period.
	DisplayMessage func(name, message string) error

	// RequestValue requests a secret or public input, with the provided prompt.
	RequestValue func(name, prompt string, secret bool) (string, error)

	// Confirm requests a confirmation with the provided prompt. The yes and no
	// value are the choices provided to the user. no may be empty. The return
	// value indicates whether the user selected the yes or no option.
	Confirm func(name, prompt, yes, no string) (choseYes bool, err error)

	// WaitTimer is invoked once (Un)Wrap has been waiting for 5 seconds on the
	// plugin, for example because the plugin is waiting for an external event
	// (e.g. a hardware token touch). Unlike the other callbacks, WaitTimer runs
	// in a separate goroutine, and if missing it's simply ignored.
	WaitTimer func(name string)
}

func (c *ClientUI) handle(name string) (ok bool, err error) {
	fmt.Println("[!] Handle called:", name)
	if c.Confirm == nil {
		return true, nil
	}

	choseYes, err := c.Confirm(name, name, "YubiKey is plugged in", "Skip this YubiKey")
	if err != nil {
		return true, nil
	}
	result := "yes"
	if !choseYes {
		result = "no"
	}

	fmt.Println("Result:", result)

	return false, nil
}
