package passlib

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFlaskAdminPassword(t *testing.T) {
	salt := "ATGUOHAELKiubahiughaerGOJAEGj"
	s := "$pbkdf2-sha512$25000$JSQEgDCGcO4dA0DondOa0w$kGqbkuv2LNeSLgmXOdi6gs.zs1WftfrjA/7baP2VTquwCjrNKEPKCSkthztxueFBL0OMD6xaN332WSEbpNmL8g"
	ok, err := VerifyPasswordWithSalt(s, "jorge13927", salt)
	require.Nil(t, err)
	assert.True(t, ok)

	s = "$pbkdf2-sha512$25000$uXcOoTTmvNfaG8O4d651zg$.CXy26eRAEfizFMH1aXzIg4/WY/LLkSV/KqrvI7y1.tIm2sSsXjFwtZB57HCq4tDtDFF9PGYVgvDSi8ITiiWmQ"
	ok, err = VerifyPasswordWithSalt(s, "admin13927", salt)
	require.Nil(t, err)
	assert.True(t, ok)

	s = "$pbkdf2-sha512$25000$sPYew7gXAqAUImRMaQ2h9A$93UjLeqGH2891m.etQCwZxTQkYxGMTlV7owxBPkjF7fcJwmoVDm/GhEUW5CutJJpyw8mgvj/jbeGv.A0atn.yw"
	ok, err = VerifyPasswordWithSalt(s, "a", salt)
	require.Nil(t, err)
	assert.True(t, ok)
}

func TestGenPasswordWithSalt(t *testing.T) {
	salt := "ATGUOHAELKiubahiughaerGOJAEGj"
	phash, err := GenPasswordWithSalt("jorge13927", salt)
	require.Nil(t, err)

	// verify with VerifyPasswordWithSalt (because the internal salt in GenPasswordWithSalt is random, so the
	// resulting phash value is unknown)
	ok, err := VerifyPasswordWithSalt(phash, "jorge13927", salt)
	require.Nil(t, err)
	assert.True(t, ok)
}

func TestGetHMAC(t *testing.T) {
	expectedHash := "YCrHFiPMHnZd9JDh7gFBhuJJOv8JQP6vBp20P1EHzG/tVcF60G15Oukn2QvEo5ItMtQDVBarhWPEZI3LtteA4Q=="
	hash := GetHMAC([]byte("a"), []byte("ATGUOHAELKiubahiughaerGOJAEGj"))
	assert.Equal(t, expectedHash, hash)
	spew.Dump(expectedHash, hash)
}
