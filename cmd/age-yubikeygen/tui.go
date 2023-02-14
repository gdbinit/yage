package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"runtime"

	"filippo.io/age/armor"
	"github.com/go-piv/piv-go/piv"
	"golang.org/x/term"
)

// l is a logger with no prefixes.
var l = log.New(os.Stderr, "", 0)

const (
	debug     = true
	KEY_CTRLC = 0x3
	KEY_ESC   = 0x1b
	KEY_ENTER = 0xd
)

func debugf(format string, v ...interface{}) {
	if debug {
		l.Printf("debug: "+format, v...)
	}
}

func printf(format string, v ...interface{}) {
	l.Printf("age-yubikeygen: "+format, v...)
}

func errorf(format string, v ...interface{}) {
	l.Printf("error: "+format, v...)
	exit(1)
}

func warningf(format string, v ...interface{}) {
	l.Printf("warning: "+format, v...)
}

func errorWithHint(error string, hints ...string) {
	l.Printf("error: %s", error)
	for _, hint := range hints {
		l.Printf("age-yubikeygen: hint: %s", hint)
	}
	exit(1)
}

// If testOnlyPanicInsteadOfExit is true, exit will set testOnlyDidExit and
// panic instead of calling os.Exit. This way, the wrapper in TestMain can
// recover the panic and return the exit code only if it was originated in exit.
var testOnlyPanicInsteadOfExit bool
var testOnlyDidExit bool

func exit(code int) {
	if testOnlyPanicInsteadOfExit {
		testOnlyDidExit = true
		panic(code)
	}
	os.Exit(code)
}

// clearLine clears the current line on the terminal, or opens a new line if
// terminal escape codes don't work.
func clearLine(out io.Writer) {
	const (
		CUI = "\033["   // Control Sequence Introducer
		CPL = CUI + "F" // Cursor Previous Line
		EL  = CUI + "K" // Erase in Line
	)

	// First, open a new line, which is guaranteed to work everywhere. Then, try
	// to erase the line above with escape codes.
	//
	// (We use CRLF instead of LF to work around an apparent bug in WSL2's
	// handling of CONOUT$. Only when running a Windows binary from WSL2, the
	// cursor would not go back to the start of the line with a simple LF.
	// Honestly, it's impressive CONIN$ and CONOUT$ work at all inside WSL2.)
	fmt.Fprintf(out, "\r\n"+CPL+EL)
}

// withTerminal runs f with the terminal input and output files, if available.
// withTerminal does not open a non-terminal stdin, so the caller does not need
// to check stdinInUse.
func withTerminal(f func(in, out *os.File) error) error {
	if runtime.GOOS == "windows" {
		in, err := os.OpenFile("CONIN$", os.O_RDWR, 0)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer out.Close()
		return f(in, out)
	} else if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		return f(tty, tty)
	} else if term.IsTerminal(int(os.Stdin.Fd())) {
		return f(os.Stdin, os.Stdin)
	} else {
		return fmt.Errorf("standard input is not a terminal, and /dev/tty is not available: %v", err)
	}
}

func printfToTerminal(format string, v ...interface{}) error {
	return withTerminal(func(_, out *os.File) error {
		_, err := fmt.Fprintf(out, "age: "+format+"\n", v...)
		return err
	})
}

// readSecret reads a value from the terminal with no echo. The prompt is ephemeral.
func readSecret(prompt string) (s []byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)
		s, err = term.ReadPassword(int(in.Fd()))
		return err
	})
	return
}

func readLine(prompt string) (s []byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)

		oldState, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), oldState)

		n := term.NewTerminal(in, "")
		line, err := n.ReadLine()
		if err != nil {
			return err
		}
		s = []byte(line)
		return nil
	})
	return
}

// readCharacter reads a single character from the terminal with no echo. The
// prompt is ephemeral.
func readCharacter(prompt string) (c byte, err error) {
	err = withTerminal(func(in, out *os.File) error {
		fmt.Fprintf(out, "%s ", prompt)
		defer clearLine(out)

		oldState, err := term.MakeRaw(int(in.Fd()))
		if err != nil {
			return err
		}
		defer term.Restore(int(in.Fd()), oldState)

		b := make([]byte, 1)
		if _, err := in.Read(b); err != nil {
			return err
		}
		c = b[0]
		return nil
	})
	return
}

func bufferTerminalInput(in io.Reader) (io.Reader, error) {
	buf := &bytes.Buffer{}
	if _, err := buf.ReadFrom(ReaderFunc(func(p []byte) (n int, err error) {
		if bytes.Contains(buf.Bytes(), []byte(armor.Footer+"\n")) {
			return 0, io.EOF
		}
		return in.Read(p)
	})); err != nil {
		return nil, err
	}
	return buf, nil
}

type ReaderFunc func(p []byte) (n int, err error)

func (f ReaderFunc) Read(p []byte) (n int, err error) { return f(p) }

type touchPolicy struct {
	label  string
	option byte
	value  piv.TouchPolicy
}

func RequestTouchPolicy(prompt string) piv.TouchPolicy {
	policy := []touchPolicy{
		{
			label:  "Always (A physical touch is required for every decryption)",
			option: '0',
			value:  piv.TouchPolicyAlways,
		},
		{
			label:  "Cached (A physical touch is required for decryption, and is cached for 15 seconds)",
			option: '1',
			value:  piv.TouchPolicyCached,
		},
		{
			label:  "Never  (A physical touch is NOT required to decrypt)",
			option: '2',
			value:  piv.TouchPolicyNever,
		},
	}

	fmt.Println(prompt)
	for _, v := range policy {
		fmt.Printf("%c) %s\n", v.option, v.label)
	}
	for {
		selection, _ := readCharacter(">")
		if selection == KEY_CTRLC || selection == KEY_ESC {
			os.Exit(1)
		}
		for _, v := range policy {
			if v.option == selection {
				return v.value
			}
		}
	}
}

type pinPolicy struct {
	label  string
	option byte
	value  piv.PINPolicy
}

// returns a valid value or exits on user cancel
func RequestPINPolicy(prompt string) piv.PINPolicy {
	policy := []pinPolicy{
		{
			label:  "Always (A PIN is required for every decryption, if set)",
			option: '0',
			value:  piv.PINPolicyAlways,
		},
		{
			label:  "Once   (A PIN is required once per session, if set)",
			option: '1',
			value:  piv.PINPolicyOnce,
		},
		{
			label:  "Never  (A PIN is NOT required to decrypt)",
			option: '2',
			value:  piv.PINPolicyNever,
		},
	}

	fmt.Println(prompt)
	for _, v := range policy {
		fmt.Printf("%c) %s\n", v.option, v.label)
	}
	for {
		selection, _ := readCharacter(">")
		if selection == KEY_CTRLC || selection == KEY_ESC {
			os.Exit(1)
		}
		for _, v := range policy {
			if v.option == selection {
				return v.value
			}
		}
	}
}
