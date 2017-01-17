package passlib

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyPassword(t *testing.T) {
	s := "$pbkdf2-sha256$1212$4vjV83LKPjQzk31VI4E0Vw$hsYF68OiOUPdDZ1Fg.fJPeq1h/gXXY7acBp9/6c.tmQ"
	ok, err := VerifyPassword(s, []byte("password"))
	require.Nil(t, err)
	assert.True(t, ok)

	s = "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww"
	ok, err = VerifyPassword(s, []byte("password"))
	require.Nil(t, err)
	assert.True(t, ok)
}

func TestPBKDF2Sha512Password(t *testing.T) {
	pass, err := PBKDF2Sha512Password([]byte("password"), "RHY0Fr3IDMSVO/RSZyb5ow", 1212)
	require.Nil(t, err)
	s := "$pbkdf2-sha512$1212$RHY0Fr3IDMSVO/RSZyb5ow$eNLfBK.eVozomMr.1gYa17k9B7KIK25NOEshvhrSX.esqY3s.FvWZViXz4KoLlQI.BzY/YTNJOiKc5gBYFYGww"
	assert.Equal(t, s, pass)
}
