package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStaleKeysFor_Version0(t *testing.T) {
	assert.Empty(t, staleKeysFor("ecdsa", "wallet-1", 0))
}

func TestStaleKeysFor_Version1(t *testing.T) {
	assert.Equal(t, []string{"ecdsa:wallet-1"}, staleKeysFor("ecdsa", "wallet-1", 1))
}

func TestStaleKeysFor_Version3(t *testing.T) {
	assert.Equal(t, []string{
		"ecdsa:wallet-1",
		"ecdsa:wallet-1_v1",
		"ecdsa:wallet-1_v2",
	}, staleKeysFor("ecdsa", "wallet-1", 3))
}
