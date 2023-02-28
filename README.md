## About

This is an [age](https://github.com/FiloSottile/age) fork with internal support for Yubikeys private key generation and storage instead of external plugins such as [age-plugin-yubikey](https://github.com/str4d/age-plugin-yubikey) or [yubage](https://github.com/tv42/yubage).

The main reasons for this are that I find it annyoing to have external plugins for this specific purpose (negating Go's awesome static binaries feature) and complicates the [gopass](https://www.gopass.pw/) fork that I want to finish next.

While I understand why it was created, I'm not a fan of the plugin design since external code from `PATH` is called and there is no authentication between the caller (age) and the plugin, which is kind of weird when exchanging critical crypto material.

I also don't like Rust (essentially a C++ like spaghetti on steroids :-X) and the Go version is incomplete (lacking key generation and not fully compatible with `age-plugin-yubikey`). And most important, I still have too much free time these days while on funemployment.

It also follows a principle to use as less external code as possible so the UI is not as nice as `age-plugin-yubikey` (key based selection instead of cursor based selection). The amount of random dependencies that certain Go projects have drives me crazy in a world of increasing supply chain attacks (yes, go mod and vendoring are nice, but less is more for me).

A complete key generator `age-yubikeygen` is available and is pretty much on par with `age-plugin-yubikey` features.

One difference versus `age-plugin-yubikey` usage is that you should initially run setup as `age-yubikeygen --setup` to make the target Yubikey ready (essentially forcing default PIN changes and migrating the management key to a PIN protected metadata slot). This is to support new and existing Yubikeys you might have.

Please notice that both `age-yubikeygen` and `age-plugin-yubikey` use the "retired key management" slots to store their keys and certificates. It's not possible to remove keys/certificates from individual slots (only all slots reset) but slot overwrite is supported.

The key generator utility also supports a full PIV reset (`age-yubikeygen --reset`) and options to change PIN and PUK. This avoids using `ykman` for these operations. **Please be aware that the PIV reset will clear all the slots, including the often used 9a, 9c, 9d, and 9e in GPG setups**. 

The `age` command code was slightly modified to parse the new identity/recipient while also still supporting `age-plugin-yubikey`.

This fork requires Go 1.20+ because it's already using latest `crypto/ecdh` package per Go 1.20 [release notes](https://go.dev/doc/go1.20#crypto/ecdh).

Both Yubikeys 4 and 5 are supported, although Yubikeys 5 are better because of [issues](https://github.com/go-piv/piv-go/issues/47) with the caching and PIN reset. For example, the `once` policy isn't really easy to support with Yubikeys 4 and it's pretty much useless for practical usage purposes, meaning, that you always need to insert PIN when doing operations. This problem doesn't occur with Yubikeys 5.

Tested on macOS x86_64 & ARM64, and Linux x86_64 & ARM64.

I have no idea if there is a point in trying to merge with upstream `age`. The reason is that `age` codebase is quite stable these days and this fork ideas might not make sense there. Its goal is pretty much to fulfill my needs. I'll leave it to Filippo to decide that. All new code follows the original `age` license.

Have fun,  
fG!

## Requirements

### Debian or Ubuntu:

```bash
sudo apt-get install pcscd libpcsclite-dev
```

## Installation

```bash
git clone https://github.com/gdbinit/yage.git
cd yage
make
sudo cp {age,age-keygen,age-yubikeygen} /usr/local/bin
```

## Usage

There is no difference using `age`, it's just a matter of using the new recipients and identities generated with `age-yubikeygen`.

The identities files aren't a secret as regular age identity files since they just contain information about the corresponding Yubikey - all private key material was generated and stored inside Yubikeys and can't be (easily) extracted.

To use `age-yubikeygen` setup must be first executed:

```bash
$ age-yubikeygen --setup
🔓 Enter PIN for YubiKey (default is 123456): 

✨ Your YubiKey is using the default PIN. Let's change it!
✨ We'll also set the PUK equal to the PIN.

🔐 The PIN is from 6 to 8 numbers, letters, or symbols. Not just numbers!
❌ Your keys will be lost if the PIN and PUK are locked after 3 incorrect tries.

🔓 Enter current PUK (default is 12345678):  
❓ Choose a new PIN/PUK:  
❓ Repeat the PIN/PUK: 

✨ Your YubiKey is using the default management key.
✨ We'll migrate it to a PIN-protected management key.
... Success!

The new management key is: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

✨ Your Yubikey is ready to be used.

```

Now a new identity can be generated:

```bash
$ age-yubikeygen
a) Slot 1 (Empty)
b) Slot 2 (Empty)
c) Slot 3 (Empty)
d) Slot 4 (Empty)
e) Slot 5 (Empty)
f) Slot 6 (Empty)
g) Slot 7 (Empty)
h) Slot 8 (Empty)
i) Slot 9 (Empty)
j) Slot 10 (Empty)
k) Slot 11 (Empty)
l) Slot 12 (Empty)
m) Slot 13 (Empty)
n) Slot 14 (Empty)
o) Slot 15 (Empty)
p) Slot 16 (Empty)
q) Slot 17 (Empty)
r) Slot 18 (Empty)
s) Slot 19 (Empty)
t) Slot 20 (Empty)
❓ Please choose slot (or press enter to use next free slot): 
❓ Name this identity [leave empty for automatic]:  

❓ Select a PIN policy:
0) Always (A PIN is required for every decryption, if set)
1) Once   (A PIN is required once per session, if set)
2) Never  (A PIN is NOT required to decrypt)
> 2

❓ Select a touch policy:
0) Always (A physical touch is required for every decryption)
1) Cached (A physical touch is required for decryption, and is cached for 15 seconds)
2) Never  (A physical touch is NOT required to decrypt)

> 0

❓ Generate new identity in slot 1? [y/n] 

🎲 Generating key...

🔓 Enter PIN for YubiKey: 
🔏 Generating certificate...
👆 Please touch the Yubikey

📝 File name to write this identity to [age-yubikey-identity-f1d4d923.txt]: 

✅ Done! This YubiKey identity is ready to go.

🔑 Here's your shiny new YubiKey recipient:

age1yubiembed1qtyc0zuw8xced8zzn9rjmvsc0dejerp0aw9yxe8ws7welfk90wkpvhgjhyr

Here are some example things you can do with it:

- Encrypt a file to this identity:
$ cat foo.txt | age -r age1yubiembed1qtyc0zuw8xced8zzn9rjmvsc0dejerp0aw9yxe8ws7welfk90wkpvhgjhyr -o foo.txt.age

- Decrypt a file with this identity:
$ cat foo.txt.age | age -d -i age-yubikey-identity-f1d4d923.txt > foo.txt

- Recreate the identity file:
$ age-yubikeygen -i --serial 5442177 --slot 1 > age-yubikey-identity-f1d4d923.txt

- Recreate the recipient:
$ age-yubikeygen -r --serial 5442177 --slot 1

⚠️  Remember: everything breaks, have a backup plan for when this YubiKey does.

```

## Other age-yubikeygen options

The PIN and PUK can be individually changed using the `--change-pin` and `--change-puk` options.

All the PIV slots can be reset using the `--reset` option. This is a nuclear option and all the certificates and keys will be wiped out, so be careful.

The list of identities stored in the Yubikey can be retrieved using `-i` or `--identity` option, while recipients list with `-r` or `--recipient`. Use together with `--slot` to recreate specific identity and recipients.
