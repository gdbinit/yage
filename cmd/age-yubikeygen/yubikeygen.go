// Copyright 2023 Pedro Vilaça (reverser@put.as). All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"time"

	"filippo.io/age/internal/bech32"
	"github.com/go-piv/piv-go/piv"
)

const (
	VERSION          = "0.2"
	BASE_SLOT        = 0x82
	WAIT_TIMEOUT     = 15 // seconds
	IDENTITY_PREFIX  = "AGE-PLUGIN-YUBIEMBED-"
	RECIPIENT_PREFIX = "age1yubiembed"
)

var USABLE_SLOTS = []uint32{0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95}

const usage = `
┌─┐┌─┐┌─┐  ┬ ┬┬ ┬┌┐ ┬┬┌─┌─┐┬ ┬┌─┐┌─┐┌┐┌
├─┤│ ┬├┤───└┬┘│ │├┴┐│├┴┐├┤ └┬┘│ ┬├┤ │││
┴ ┴└─┘└─┘   ┴ └─┘└─┘┴┴ ┴└─┘ ┴ └─┘└─┘┘└┘
 Generate a Yubikey based age identity

Usage:
	age-yubikeygen [OPTIONS]

Options:
	-h, --help                  Print this help message and exit.
	-V, --version               Print version info and exit.
	-i, --identity              Print identities stored in selected YubiKey.
	-r, --recipient             Print recipients for age identities in selected YubiKey.
	--setup                     Initial setup to make Yubikey ready for age.
	--reset                     Reset all the PIV slots (highly destructive option!).
	--change-pin                Change PIV PIN.
	--change-puk                Change PIV PUK.
	--slot SLOT                 Specify which slot (1 to 20) to use together with -i or -r.
	--serial SERIAL             Specify which YubiKey to use, if more than one is plugged in.
`

func main() {
	flag.Usage = func() { fmt.Fprintf(os.Stderr, "%s\n", usage) }
	var (
		identityFlag  bool
		recipientFlag bool
		versionFlag   bool
		helpFlag      bool
		resetFlag     bool
		setupFlag     bool
		changePUKFlag bool
		changePINFlag bool
		slotFlag      uint
		serialFlag    uint
	)

	flag.BoolVar(&helpFlag, "h", false, "Print this help message and exit.")
	flag.BoolVar(&helpFlag, "help", false, "Print this help message and exit.")
	flag.BoolVar(&versionFlag, "V", false, "Print version info and exit.")
	flag.BoolVar(&versionFlag, "version", false, "Print version info and exit.")
	flag.BoolVar(&identityFlag, "i", false, "Print identities stored in selected Yubikey.")
	flag.BoolVar(&identityFlag, "identity", false, "Print identities stored in selected Yubikey.")
	flag.BoolVar(&recipientFlag, "r", false, "Print recipients for age identities in selected YubiKey.")
	flag.BoolVar(&recipientFlag, "recipient", false, "Print recipients for age identities in selected YubiKey.")
	flag.BoolVar(&resetFlag, "reset", false, "Reset all the PIV slots (highly destructive option!).")
	flag.BoolVar(&setupFlag, "setup", false, "Initial setup to make Yubikey ready for age.")
	flag.BoolVar(&changePINFlag, "change-pin", false, "Change PIV PIN.")
	flag.BoolVar(&changePUKFlag, "change-puk", false, "Change PIV PUK.")
	flag.UintVar(&slotFlag, "slot", 0, "Specify which slot (1 to 20) to use together with -i or -r.")
	flag.UintVar(&serialFlag, "serial", 0, "Specify which YubiKey to use, if more than one is plugged in.")
	flag.Parse()

	var err error

	serial := uint32(serialFlag)

	switch {
	case helpFlag:
		flag.Usage()
		os.Exit(0)
	case versionFlag:
		fmt.Printf("age-yubikeygen %s\n", VERSION)
		os.Exit(0)
	case identityFlag:
		err = listIdentities(serial, slotFlag)
		if err != nil {
			errorf("%v", err)
		}
		os.Exit(0)
	case recipientFlag:
		err = listRecipients(serial, slotFlag)
		if err != nil {
			errorf("%v", err)
		}
		os.Exit(0)
	case changePINFlag:
		err = changePIN(serial)
		if err != nil {
			errorf("%v", err)
		}
		os.Exit(0)
	case changePUKFlag:
		err = changePUK(serial)
		if err != nil {
			errorf("%v", err)
		}
		os.Exit(0)
	case setupFlag:
		err = setupYubikey((serial))
		if err != nil {
			errorf("%v", err)
		}
		os.Exit(0)
	// nuke all the slots - beware!
	case resetFlag:
		nukeEverything(serial)
		os.Exit(0)
	}

	// the default is to generate a new key
	generateInteractive()
}

func generateInteractive() {
	yk, err := openYubikey(0)
	if err != nil {
		errorf("%v", err)
	}
	defer yk.Close()
	slot := selectSlots(yk)

	// Certificate Name
	commonName, err := readLine("❓ Name this identity [leave empty for automatic]: ")
	if err != nil {
		errorf("%v", err)
	}
	// PIN Policy
	pinpolicy := RequestPINPolicy("❓ Select a PIN policy:")
	// Touch Policy
	touchpolicy := RequestTouchPolicy("❓ Select a touch policy:")
	fmt.Println("")
	for {
		prompt := fmt.Sprintf("❓ Generate new identity in slot %d? [y/n]", slot-BASE_SLOT+1)
		answer, err := readCharacter(prompt)
		if err != nil {
			fmt.Printf("error: %v\n", err)
			continue
		}
		switch answer {
		case 'y', 'Y':
			generateIdentity(yk, commonName, pinpolicy, touchpolicy, slot)
			os.Exit(0)
		case 'n', 'N':
			os.Exit(0)
		case KEY_CTRLC, KEY_ESC:
			os.Exit(1)
		}
	}
}

// nukeEverything resets the PIV slots (includes regular 9a 9c 9d 9e commonly used in GPG guides)
func nukeEverything(serial uint32) {
	yk, err := openYubikey(serial)
	if err != nil {
		errorf("%v", err)
	}
	defer yk.Close()

	answer, err := readLine(`☠️  Do you want to reset the PIV applet? This will delete all PIV keys. Type "delete": `)
	if err != nil {
		errorf("%v", err)
	}
	if string(answer) != "delete" {
		errorf("Wrong answer! Aborting...")
	}

	fmt.Println("Resetting YubiKey PIV applet...")
	if err := yk.Reset(); err != nil {
		errorf("Failed to reset YubiKey: %v", err)
	}
}

func changePIN(serial uint32) error {

	yk, err := openYubikey(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	userPIN, err := readSecret("🔓 Enter current PIN for YubiKey:")
	if err != nil {
		return fmt.Errorf("user PIN input failed: %v", err)
	}

	for {
		newPIN, err := readSecret("❓ Choose a new PIN: ")
		if err != nil {
			fmt.Printf("error: New PIN input failed: %v\n", err)
			continue
		}
		// check PUK length
		if len(newPIN) < 6 || len(newPIN) > 8 {
			fmt.Println("error: The new PIN needs to be between 6 to 8 characters.")
			continue
		}

		if string(newPIN) == piv.DefaultPIN || string(newPIN) == piv.DefaultPUK {
			fmt.Println("error: Please don't use the default PIN/PUK.")
			continue
		}

		newPIN2, err := readSecret("❓ Repeat the PIN:")
		if err != nil {
			fmt.Printf("error: Repeat PIN input failed: %v\n", err)
			continue
		}
		if !bytes.Equal(newPIN, newPIN2) {
			fmt.Println("error: PINs don't match")
			continue
		}
		// change PIN
		err = yk.SetPIN(string(userPIN), string(newPIN))
		if err != nil {
			return fmt.Errorf("SetPIN failed: %v", err)
		}
		break
	}
	fmt.Println("✨ New PIN is set.")
	return nil
}

func changePUK(serial uint32) error {

	yk, err := openYubikey(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	userPUK, err := readSecret("🔓 Enter current PUK for YubiKey:")
	if err != nil {
		return fmt.Errorf("user PUK input failed: %v", err)
	}

	for {
		newPUK, err := readSecret("❓ Choose a new PUK: ")
		if err != nil {
			fmt.Printf("error: New PUK input failed: %v\n", err)
			continue
		}
		// check PUK length
		if len(newPUK) < 6 || len(newPUK) > 8 {
			fmt.Println("error: The new PUK needs to be between 6 to 8 characters.")
			continue
		}

		if string(newPUK) == piv.DefaultPIN || string(newPUK) == piv.DefaultPUK {
			fmt.Println("error: Please don't use the default PIN/PUK.")
			continue
		}

		newPUK2, err := readSecret("❓ Repeat the PUK:")
		if err != nil {
			fmt.Printf("error: Repeat PUK input failed: %v\n", err)
			continue
		}
		if !bytes.Equal(newPUK, newPUK2) {
			fmt.Println("error: PUKs don't match")
			continue
		}
		// change PUK
		err = yk.SetPUK(string(userPUK), string(newPUK))
		if err != nil {
			return fmt.Errorf("SetPUK failed: %v", err)
		}
		break
	}
	fmt.Println("✨ New PUK is set.")
	return nil
}

func setupYubikey(serial uint32) error {

	yk, err := openYubikey(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	// we can't test for default PINs behind the user because we might lock out the Yubikey
	// given the limited number of retries we have

	userPIN, err := readSecret("🔓 Enter PIN for YubiKey (default is 123456):")
	if err != nil {
		return fmt.Errorf("user PIN input failed: %v", err)
	}
	// change and set the PIN protected management key metadata so we don't need to use management key
	// this only supports a new Yubikey - for already setup keys with modified PIN/management key
	// use the option to migrate the management key
	if string(userPIN) == piv.DefaultPIN {
		fmt.Println("✨ Your YubiKey is using the default PIN. Let's change it!")
		fmt.Println("✨ We'll also set the PUK equal to the PIN.")
		fmt.Println("")
		fmt.Println("🔐 The PIN is from 6 to 8 numbers, letters, or symbols. Not just numbers!")
		fmt.Println("❌ Your keys will be lost if the PIN and PUK are locked after 3 incorrect tries.")
		fmt.Println("")
		userPUK, err := readSecret("🔓 Enter current PUK (default is 12345678): ")
		if err != nil {
			return fmt.Errorf("current PUK input failed: %v", err)
		}
		// test the PUK
		for {
			newPUK, err := readSecret("❓ Choose a new PIN/PUK: ")
			if err != nil {
				fmt.Printf("error: New PIN/PUK input failed: %v\n", err)
				continue
			}
			// check PUK length
			if len(newPUK) < 6 || len(newPUK) > 8 {
				fmt.Println("error: The PIN/PUK needs to be between 6 to 8 characters.")
				continue
			}

			if string(newPUK) == piv.DefaultPIN || string(newPUK) == piv.DefaultPUK {
				fmt.Println("error: Please don't use the default PIN/PUK.")
				continue
			}

			newPUK2, err := readSecret("❓ Repeat the PIN/PUK:")
			if err != nil {
				fmt.Printf("error: Repeat PIN/PUK input failed: %v\n", err)
				continue
			}
			if !bytes.Equal(newPUK, newPUK2) {
				fmt.Println("error: PINs don't match")
				continue
			}
			// change PUK
			err = yk.SetPUK(string(userPUK), string(newPUK))
			if err != nil {
				return fmt.Errorf("SetPUK failed: %v", err)
			}
			// change PIN
			err = yk.SetPIN(piv.DefaultPIN, string(newPUK))
			if err != nil {
				return fmt.Errorf("SetPIN failed: %v", err)
			}
			fmt.Println("✨ Your YubiKey is using the default management key.")
			fmt.Println("✨ We'll migrate it to a PIN-protected management key.")
			// Migrate to a PIN-protected management key
			var newKey [24]byte
			if _, err := rand.Read(newKey[:]); err != nil {
				errorf("failed to generate new random management key: %v", err)
			}
			// XXX: lacking if default pin is set but management key was changed
			err = yk.SetManagementKey(piv.DefaultManagementKey, newKey)
			if err != nil {
				// XXX: warn user that management key is not default
				return fmt.Errorf("SetManagementKey failed: %v", err)
			}
			err = yk.SetMetadata(newKey, &piv.Metadata{ManagementKey: &newKey})
			if err != nil {
				return fmt.Errorf("SetMetadata failed: %v", err)
			}
			fmt.Println("... Success!")
			fmt.Println("")
			fmt.Println("The new management key is:", hex.EncodeToString(newKey[:]))
			fmt.Println("")
			fmt.Println("✨ Your Yubikey is ready to be used.")
			fmt.Println("")
			return nil
		}
	}

	// it's not the default PIN so we need to test if there is PIN protected metadata
	// and update it if there isn't

	m, err := yk.Metadata(string(userPIN))
	if err != nil {
		// if m is nil then it means default pin failed
		// if m is empty it means pin worked but metadata doesn't exist
		if m == nil {
			return err
		}
	}
	// if there is key in metadata then we have nothing to do here
	if m.ManagementKey != nil {
		fmt.Println("❗️ Management key is already PIN protected.")
		fmt.Println("")
		fmt.Println("✨ Your Yubikey is ready to be used.")
		fmt.Println("")
		return nil
	}
	// otherwise we have work to do
	fmt.Println("⚠️  Management key is not PIN protected!")
	fmt.Println("")
	// we don't know if user already changed the management key or it's still the default
	mgKey, err := readSecret("❓ Enter current management key (24 chars long) [leave empty for default]:")
	if err != nil {
		return err
	}

	if len(mgKey) > 0 && len(mgKey) != 48 {
		return fmt.Errorf("management key length should be 48 chars long (24 bytes)")
	}

	// still using the default management key
	if len(mgKey) == 0 {
		fmt.Println("✨ Your YubiKey is using the default management key.")
		fmt.Println("✨ We'll migrate it to a PIN-protected random management key.")
		var newMgKey [24]byte
		if _, err := rand.Read(newMgKey[:]); err != nil {
			errorf("failed to generate new random management key: %v", err)
		}

		err = yk.SetManagementKey(piv.DefaultManagementKey, newMgKey)
		if err != nil {
			// XXX: better error message to the user here
			return err
		}
		// finally set PIN protected metadata for the new management key
		err = yk.SetMetadata(newMgKey, &piv.Metadata{ManagementKey: &newMgKey})
		if err != nil {
			return err
		}
		fmt.Println("")
		fmt.Println("The new key is:", hex.EncodeToString(newMgKey[:]))
		fmt.Println("")
		fmt.Println("✨ Your Yubikey is ready to be used.")
		fmt.Println("")
		return nil
	} else {
		// in this case the default key was changed but set as PIN protected
		fmt.Println("Migrating current management key to PIN protected...")
		// we need to convert the input string to hex bytes otherwise we get its ascii bytes
		k, err := hex.DecodeString(string(mgKey))
		if err != nil {
			return err
		}
		var key [24]byte
		copy(key[:], k[:24])
		// finally set PIN protected metadata for the new management key
		err = yk.SetMetadata(key, &piv.Metadata{ManagementKey: &key})
		if err != nil {
			return err
		}
		fmt.Println("")
		fmt.Println("✨ Your Yubikey is ready to be used.")
		fmt.Println("")
		return nil
	}
}

// unlockManagement unlocks the PIN protected management key
func unlockManagement(yk *piv.YubiKey) (m *piv.Metadata, err error) {
	userPIN, err := readSecret("🔓 Enter PIN for YubiKey:")
	if err != nil {
		return nil, fmt.Errorf("user PIN input failed: %v", err)
	}
	if string(userPIN) == piv.DefaultPUK || string(userPIN) == piv.DefaultPIN {
		return nil, fmt.Errorf("a default PIN/PUK is set. Please run setup first")
	}
	// try to unlock management key stored in the metadata
	// this assumes it was previously migrated to PIN-protected management key
	m, err = yk.Metadata(string(userPIN))
	if err == nil && m.ManagementKey == nil {
		err = fmt.Errorf("no PIN protected metadata. Please run setup first")
	}
	return
}

// generateIdentity generates a new Yubikey based age Identity
func generateIdentity(yk *piv.YubiKey, commonName []byte, pinPolicy piv.PINPolicy, touchPolicy piv.TouchPolicy, slotNr uint32) {

	fmt.Println("")
	fmt.Println("🎲 Generating key...")
	fmt.Println("")

	slot, ok := piv.RetiredKeyManagementSlot(slotNr)
	if !ok {
		errorf("failed to access slot %d", slotNr)
	}

	key := piv.Key{
		Algorithm:   piv.AlgorithmEC256,
		PINPolicy:   pinPolicy,
		TouchPolicy: touchPolicy,
	}

	// management key is stored in the metadata
	// so we don't need the management keys
	// but can unlock it using the PIN
	mt, err := unlockManagement(yk)
	if err != nil {
		errorf("Failed to unlock management key: %v", err)
	}

	fmt.Println("")
	fmt.Println("🔏 Generating certificate...")

	pub, err := yk.GenerateKey(*mt.ManagementKey, slot, key)
	if err != nil {
		errorf("%v", err)
	}
	ecdsaPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		errorf("Public key is not of type *ecdsa.PublicKey: %T", pub)
	}

	// generate a compressed version
	pivCompressed := elliptic.MarshalCompressed(ecdsaPub.Curve, ecdsaPub.X, ecdsaPub.Y)
	// age-plugin-yubikey hashes directly the compressed bytes to generate the tag
	pivHash := sha256.Sum256(pivCompressed)
	// pivTag := base64.RawStdEncoding.EncodeToString(pivHash[:4])

	// per documentation the PINPrompt method is only called when needed
	// so we can pass it like this to all options
	auth := piv.KeyAuth{
		PINPrompt: func() (string, error) {
			pin, _ := readSecret("❓ Please insert PIN:")
			return string(pin), nil
		},
	}

	priv, err := yk.PrivateKey(slot, pub, auth)
	if err != nil {
		errorf("Getting private key: %v", err)
	}

	var cn string
	if len(commonName) == 0 {
		cn = "age identity " + hex.EncodeToString(pivHash[:4])
	} else {
		cn = string(commonName)
	}

	template := &x509.Certificate{
		Subject: pkix.Name{
			Organization:       []string{"age-yubikeygen"},
			OrganizationalUnit: []string{VERSION},
			CommonName:         cn,
		},
		NotAfter:     time.Now().AddDate(42, 0, 0),
		NotBefore:    time.Now(),
		SerialNumber: randomSerialNumber(),
		KeyUsage:     x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}

	// this is a bit out of sync if there is a PINPrompt being issued
	// because it's kind of async so this message will show up first
	// then the PINPrompt and then the message will be alone because pin prompt
	// disappears
	if touchPolicy == piv.TouchPolicyNever {
		// nothing to show up
	} else {
		// this will be true if out of the 15 cached touch for piv.TouchPolicyCached
		// can we detect if touch is needed? unless the user is generating more than one
		// key in sequence this shouldn't be a problem
		// age-plugin-yubikey has the same problem showing this message when it's cached
		fmt.Println("👆 Please touch the Yubikey")
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		errorf("Failed to generate certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		errorf("Failed to parse certificate: %v", err)
	}
	// key is the management key that was randomly generated
	if err := yk.SetCertificate(*mt.ManagementKey, slot, cert); err != nil {
		errorf("Failed to store certificate: %v", err)
	}

	// print the recipient - just encoding of the public key
	recipient, err := bech32.Encode(RECIPIENT_PREFIX, pivCompressed)
	// this will leave us in a inconsistent state - key generated but nothing displayed to the user
	// if things are ok inside the Yubikey user can always regenerate with -i and -r options
	if err != nil {
		errorf("Failed to encode recipient: %v", err)
	}

	// identity is serial + slot + tag
	serial, err := yk.Serial()
	if err != nil {
		errorf("Failed to retrieve Yubikey serial number: %v", err)
	}
	serialBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(serialBuf, serial)
	encodeBuf := make([]byte, 9)
	copy(encodeBuf, serialBuf)
	encodeBuf[4] = byte(slotNr)
	copy(encodeBuf[5:], pivHash[:4])
	identity, _ := bech32.Encode(IDENTITY_PREFIX, encodeBuf)

	fmt.Println("")
	path := fmt.Sprintf("age-yubikey-identity-%s.txt", hex.EncodeToString(pivHash[:4]))
	question := fmt.Sprintf("📝 File name to write this identity to [%s]:", path)
	answer, err := readLine(question)
	if err != nil {
		errorf("%v", err)
	}
	if len(answer) > 0 {
		path = string(answer)
	}

	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		errorf("Failed to open output file %q: %v", path, err)
	}
	defer func() {
		if err := f.Close(); err != nil {
			errorf("Failed to close output file %q: %v", path, err)
		}
	}()

	fmt.Fprintf(f, "#       Serial: %d, Slot: 0x%x\n", serial, slotNr)
	fmt.Fprintf(f, "#         Name: %s\n", cn)
	fmt.Fprintf(f, "#      Created: %s\n", cert.NotBefore)
	fmt.Fprintf(f, "#   PIN policy: %s\n", pinPolicyDesc[pinPolicy])
	fmt.Fprintf(f, "# Touch policy: %s\n", touchPolicyDesc[touchPolicy])
	fmt.Fprintf(f, "#    Recipient: %s\n", recipient)
	fmt.Fprintf(f, "%s\n\n", identity)

	fmt.Println("")
	fmt.Println("✅ Done! This YubiKey identity is ready to go.")
	fmt.Println("")
	fmt.Println("🔑 Here's your shiny new YubiKey recipient:")
	fmt.Printf("%s\n", recipient)
	fmt.Println("")
	fmt.Println("Here are some example things you can do with it:")
	fmt.Println("")
	fmt.Println("- Encrypt a file to this identity:")
	fmt.Printf("$ cat foo.txt | age -r %s -o foo.txt.age\n", recipient)
	fmt.Println("")
	fmt.Println("- Decrypt a file with this identity:")
	fmt.Printf("$ cat foo.txt.age | age -d -i %s > foo.txt\n", path)
	fmt.Println("")
	fmt.Println("- Recreate the identity file:")
	fmt.Printf("$ age-yubikeygen -i --serial %d --slot %d > %s\n", serial, slotNr-BASE_SLOT+1, path)
	fmt.Println("")
	fmt.Println("- Recreate the recipient:")
	fmt.Printf("$ age-yubikeygen -r --serial %d --slot %d\n", serial, slotNr-BASE_SLOT+1)
	fmt.Println("")
	fmt.Println("⚠️  Remember: everything breaks, have a backup plan for when this YubiKey does.")
}

// selectSlots extracts information about all retired slots and presents their contents
// and asks user which slot he wants to use
func selectSlots(yk *piv.YubiKey) uint32 {

	slots := make([]*x509.Certificate, len(USABLE_SLOTS))

	for i, v := range USABLE_SLOTS {
		s, ok := piv.RetiredKeyManagementSlot(v)
		if !ok {
			continue
		}
		cert, err := yk.Certificate(s)
		if err != nil {
			continue
		}
		slots[i] = cert
	}

	// show up all slots
	for k, v := range slots {
		s := string(rune(k + 0x61))
		if v != nil {
			switch v.PublicKey.(type) {
			case *ecdsa.PublicKey:
				fmt.Printf("%s) Slot %d (%v, %v)\n", s, k+1, v.Issuer.CommonName, v.NotBefore)
			default:
				fmt.Printf("%s) Slot %d (Unusable)\n", s, k+1)
			}
		} else {
			fmt.Printf("%s) Slot %d (Empty)\n", s, k+1)
		}
	}

	slotId := -1
	auto := false
	for {
		option, err := readCharacter("❓ Please choose slot (or press enter to use next free slot):")
		if err != nil {
			fmt.Printf("error: %v\n", err)
			continue
		}
		value := int(option)
		if value == KEY_CTRLC || value == KEY_ESC {
			fmt.Println("warning: user cancelled input")
			os.Exit(0)
		} else if value == KEY_ENTER { // enter
			auto = true
			break
		} else if value >= 0x61 && value < 0x61+len(slots) {
			slotId = value - 0x61
			break
		} else {
			fmt.Printf("Bad option selected. ")
		}
	}

	if auto {
		for k, v := range slots {
			if v == nil {
				slotId = k
				break
			}
		}
		if slotId == -1 {
			errorf("No free slots available. Please overwrite a slot, clear the current Yubikey, or use another Yubikey.")
		}
	}

	// verify if selected slot already contains a certificate
	if slots[slotId] != nil {
		for {
			answer, err := readCharacter("⚠️  Selected slot already contains a certificate. Do you want to overwrite it? (y/n)")
			if err != nil {
				fmt.Printf("error: %v\n", err)
				continue
			}
			switch answer {
			case 'y', 'Y':
				return uint32(slotId + BASE_SLOT)
			case 'n', 'N':
				os.Exit(0)
			case KEY_CTRLC, KEY_ESC:
				os.Exit(1)
			}
		}
	}
	return uint32(slotId + BASE_SLOT)
}

// openBySerial tries to open a Yubikey by serial number.
// User is responsible for closing the returned handle
func openBySerial(serial uint32) (*piv.YubiKey, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		fmt.Printf("Please insert the Yubikey with serial %d.\n", serial)
		cards, _ = waitForYubi()
	}

	for _, v := range cards {
		yk, err := piv.Open(v)
		if err != nil {
			continue
		}
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
	return nil, fmt.Errorf("could not find Yubikey with serial %d", serial)
}

// openYubikey returns a handle to a Yubikey. User is responsible for closing it.
// Presents a choice list if there are multiple Yubikeys connected.
func openYubikey(serial uint32) (yk *piv.YubiKey, err error) {
	if serial > 0 {
		yk, err = openBySerial(serial)
		if err != nil {
			return nil, err
		}
		return yk, nil
	}

	cards, err := piv.Cards()
	if err != nil {
		return nil, err
	}
	if len(cards) == 0 {
		fmt.Println("No Yubikey(s) found. Please insert a Yubikey.")
		cards, _ = waitForYubi()
	}

	if len(cards) == 1 {
		yk, err = piv.Open(cards[0])
		if err != nil {
			return nil, err
		}
		return yk, nil
	} else {
		i := 0
		fmt.Println("Available keys:")
		locked := false
		for _, v := range cards {
			// cards might return multiple yubikeys but if they are in use by an agent
			// such as gpg we will fail to open them here and still present a multiple
			// selection dialog - for example with two keys plugged in but one locked
			// by gpg agent then only one shows up in the multiple selection dialog
			// against what is usually expected. maybe not worth the trouble for now
			// to implement a workaround (test all available cards and then make the
			// decision on the amount of available cards - of course there is always
			// a TOCTOU where the user can remove the key or get assigned to an agent)
			yk, err = piv.Open(v)
			if err != nil {
				i++
				locked = true
				continue
			}
			if serial, err := yk.Serial(); err == nil {
				fmt.Printf("%c) %s (Serial: %d)\n", i+0x61, v, serial)
			}
			i++
			yk.Close()
		}
		if locked {
			fmt.Println("⚠️   Multiple Yubikeys detected but some might be locked to other agents and unavailable")
		}
		for {
			option, _ := readCharacter("❓ Please select Yubikey (q to quit):")
			if option == 'q' || option == KEY_CTRLC || option == KEY_ESC {
				os.Exit(0)
			}
			if int(option) < 0x61 {
				errorf("Bad value.")
			}
			n := int(option) - 0x61
			if n >= len(cards) {
				fmt.Println("Option out of bounds")
				continue
			}
			yk, err = piv.Open(cards[n])
			if err != nil {
				return nil, err
			}
			return yk, nil
		}
	}
}

var pinPolicyDesc = map[piv.PINPolicy]string{
	piv.PINPolicyNever:  "Never  (A PIN is NOT required to decrypt)",
	piv.PINPolicyOnce:   "Once   (A PIN is required once per session, if set)",
	piv.PINPolicyAlways: "Always (A PIN is required for every decryption, if set)",
}
var touchPolicyDesc = map[piv.TouchPolicy]string{
	piv.TouchPolicyNever:  "Never  (A physical touch is NOT required to decrypt)",
	piv.TouchPolicyAlways: "Always (A physical touch is required for every decryption)",
	piv.TouchPolicyCached: "Cached (A physical touch is required for decryption, and is cached for 15 seconds)",
}

type slotInfo struct {
	serial    uint32
	slot      uint32
	name      string
	org       string
	date      time.Time
	pin       string
	touch     string
	recipient string
	identity  string
}

// getSlotInfoViaAttestation retrieves the slot information via attestation
// it's slower because it needs to talk to the Yubikey per slot
// alternative is to encode some of the information in policy extension oid as age-plugin-yubikey does
func getSlotInfoViaAttestation(yk *piv.YubiKey, attestationCert *x509.Certificate, slot uint32) (slotInfo, error) {
	s, ok := piv.RetiredKeyManagementSlot(slot)
	if !ok {
		return slotInfo{}, fmt.Errorf("invalid slot")
	}
	cert, err := yk.Certificate(s)
	if err != nil {
		return slotInfo{}, err
	}
	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return slotInfo{}, fmt.Errorf("slot doesn't contain supported ecdsa key")
	}

	if len(cert.Issuer.Organization) > 0 {
		if cert.Issuer.Organization[0] != "age-yubikeygen" {
			return slotInfo{}, fmt.Errorf("not a age-yubikeygen slot")
		}
	} else {
		return slotInfo{}, fmt.Errorf("not a age-yubikeygen slot")
	}

	// retrieve the information from the slot certificate via attestation
	// this is slower versus using certificate policy extension
	acert, err := yk.Attest(s)
	if err != nil {
		return slotInfo{}, err
	}

	atest, err := piv.Verify(attestationCert, acert)
	if err != nil {
		return slotInfo{}, err
	}

	// generate a compressed version
	pivCompressed := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	// age-plugin-yubikey hashes directly the compressed bytes to generate the tag
	pivHash := sha256.Sum256(pivCompressed)

	// print the recipient - just encoding of the public key
	recipient, err := bech32.Encode(RECIPIENT_PREFIX, pivCompressed)
	if err != nil {
		return slotInfo{}, err
	}

	serialBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(serialBuf, atest.Serial)
	encodeBuf := make([]byte, 9)
	copy(encodeBuf, serialBuf)
	encodeBuf[4] = byte(atest.Slot.Key)
	copy(encodeBuf[5:], pivHash[:4])
	identity, err := bech32.Encode(IDENTITY_PREFIX, encodeBuf)
	if err != nil {
		return slotInfo{}, err
	}

	ret := slotInfo{
		serial:    atest.Serial,
		slot:      atest.Slot.Key,
		name:      cert.Issuer.CommonName,
		org:       cert.Issuer.Organization[0], // only certs with at least one element can reach here
		date:      cert.NotBefore,
		pin:       pinPolicyDesc[atest.PINPolicy],
		touch:     touchPolicyDesc[atest.TouchPolicy],
		recipient: recipient,
		identity:  identity,
	}
	return ret, nil
}

func printIdentity(s *slotInfo) {
	fmt.Printf("#       Serial: %d, Slot: %d (0x%x)\n", s.serial, s.slot-BASE_SLOT+1, s.slot)
	fmt.Printf("#         Name: %s\n", s.name)
	fmt.Printf("#      Created: %s\n", s.date)
	fmt.Printf("#   PIN policy: %s\n", s.pin)
	fmt.Printf("# Touch policy: %s\n", s.touch)
	fmt.Printf("#    Recipient: %s\n", s.recipient)
	fmt.Printf("%s\n\n", s.identity)
}

func listIdentities(serial uint32, slot uint) (err error) {
	yk, err := openYubikey(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	attestationCert, err := yk.AttestationCertificate()
	if err != nil {
		return err
	}

	// specific slot requested
	if slot > 0 {
		// user selects from index 1 but internally we start at index 0 - meh!
		slot--
		slotinfo, err := getSlotInfoViaAttestation(yk, attestationCert, uint32(slot)+BASE_SLOT)
		if err != nil {
			return err
		}
		printIdentity(&slotinfo)
	} else {
		count := 0
		for _, v := range USABLE_SLOTS {
			slotinfo, err := getSlotInfoViaAttestation(yk, attestationCert, v)
			if err != nil {
				continue
			}
			printIdentity(&slotinfo)
			count++
		}
		if count == 0 {
			fmt.Println("⚠️  No identities found in the selected Yubikey")
		}
	}
	return nil
}

func printRecipient(s *slotInfo) {
	fmt.Printf("#       Serial: %d, Slot: %d (0x%x)\n", s.serial, s.slot-BASE_SLOT+1, s.slot)
	fmt.Printf("#         Name: %s\n", s.name)
	fmt.Printf("#      Created: %s\n", s.date)
	fmt.Printf("#   PIN policy: %s\n", s.pin)
	fmt.Printf("# Touch policy: %s\n", s.touch)
	fmt.Printf("%s\n\n", s.recipient)
}

func listRecipients(serial uint32, slot uint) (err error) {
	yk, err := openYubikey(serial)
	if err != nil {
		return err
	}
	defer yk.Close()

	attestationCert, err := yk.AttestationCertificate()
	if err != nil {
		return err
	}

	// specific slot requested
	if slot > 0 {
		// user selects from index 1 but internally we start at index 0 - meh!
		slot--
		slotinfo, err := getSlotInfoViaAttestation(yk, attestationCert, uint32(slot)+BASE_SLOT)
		if err != nil {
			return err
		}
		printRecipient(&slotinfo)
	} else {
		count := 0
		for _, v := range USABLE_SLOTS {
			slotinfo, err := getSlotInfoViaAttestation(yk, attestationCert, v)
			if err != nil {
				continue
			}
			printRecipient(&slotinfo)
			count++
		}
		if count == 0 {
			fmt.Println("⚠️  No recipients found in the selected Yubikey")
		}
	}
	return nil
}

func waitForYubi() ([]string, error) {
	defer time.AfterFunc(WAIT_TIMEOUT*time.Second, func() {
		fmt.Println("Error: Timed out while waiting for a YubiKey to be inserted.")
		os.Exit(0)
	}).Stop()
	for {
		cards, err := piv.Cards()
		if err != nil {
			return nil, err
		}
		if len(cards) > 0 {
			return cards, nil
		}
		time.Sleep(1 * time.Second)
	}
}

// generate a random x509 certificate serial number
func randomSerialNumber() *big.Int {
	// ripped out from yubikey-agent source code
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		errorf("Failed to generate serial number: %v", err)
	}
	return serialNumber
}
