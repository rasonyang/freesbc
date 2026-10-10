package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/freesbc/freesbc/internal/config"
)

// maxPasswordLine bounds the stdin read; bcrypt rejects anything over 72
// bytes anyway.
const maxPasswordLine = 4096

// hashPasswordCmd runs `freesbc hash-password` on the real terminal and
// streams. The password is never an argument: it would land in shell history
// and the process list, so anything but -h/--help is a usage error.
func hashPasswordCmd(args []string) int {
	if len(args) == 1 && (args[0] == "-h" || args[0] == "--help") {
		fmt.Print(usage)
		return 0
	}
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "freesbc hash-password: unexpected argument %q (the password is read from the terminal or stdin, never an argument)\n\n%s", args[0], usage)
		return 2
	}
	var readPass func() ([]byte, error)
	if fd := int(os.Stdin.Fd()); term.IsTerminal(fd) {
		readPass = func() ([]byte, error) { return term.ReadPassword(fd) }
	}
	return hashPassword(os.Stdin, os.Stdout, os.Stderr, readPass)
}

// hashPassword prints the bcrypt hash of a password to stdout and returns the
// exit code. readPass reads one line without echo and is nil when stdin is
// not a terminal; then one line is read from in. Prompts and errors go to
// stderr, so stdout carries only the hash.
func hashPassword(in io.Reader, stdout, stderr io.Writer, readPass func() ([]byte, error)) int {
	var pw []byte
	if readPass != nil {
		var err error
		if pw, err = promptTwice(stderr, readPass); err != nil {
			fmt.Fprintf(stderr, "freesbc hash-password: %v\n", err)
			return 1
		}
	} else {
		line, err := bufio.NewReader(io.LimitReader(in, maxPasswordLine)).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			fmt.Fprintf(stderr, "freesbc hash-password: read stdin: %v\n", err)
			return 1
		}
		// Only the line ending goes; other whitespace is part of the password.
		pw = []byte(strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r"))
	}
	if len(pw) == 0 {
		fmt.Fprintln(stderr, "freesbc hash-password: the password is empty")
		return 1
	}
	hash, err := bcrypt.GenerateFromPassword(pw, config.MinBcryptCost)
	if errors.Is(err, bcrypt.ErrPasswordTooLong) {
		fmt.Fprintln(stderr, "freesbc hash-password: the password is longer than 72 bytes, which bcrypt cannot use; choose a shorter one")
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "freesbc hash-password: %v\n", err)
		return 1
	}
	fmt.Fprintf(stdout, "%s\n", hash)
	return 0
}

// promptTwice asks for the password and its confirmation, which must match.
func promptTwice(stderr io.Writer, readPass func() ([]byte, error)) ([]byte, error) {
	ask := func(prompt string) ([]byte, error) {
		fmt.Fprint(stderr, prompt)
		pw, err := readPass()
		fmt.Fprintln(stderr) // the terminal did not echo the Enter
		return pw, err
	}
	first, err := ask("Password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	second, err := ask("Confirm password: ")
	if err != nil {
		return nil, fmt.Errorf("read password: %w", err)
	}
	if string(first) != string(second) {
		return nil, errors.New("the passwords do not match")
	}
	return first, nil
}
