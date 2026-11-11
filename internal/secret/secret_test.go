package secret

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetSecret(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(filename, []byte(" secret$VALUE \r\n\n"), 0600))
	empty := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.WriteFile(empty, nil, 0600))
	cases := []struct {
		name      string
		plaintext string
		filename  string
		want      string
		wantError bool
	}{
		{
			name:      "plaintext takes precedence",
			plaintext: " literal$VALUE\r\n",
			filename:  filename + ".missing",
			want:      " literal$VALUE\r\n",
		},
		{
			name:     "file contents preserved",
			filename: filename,
			want:     " secret$VALUE \r\n\n",
		},
		{
			name: "unset",
		},
		{
			name:     "empty file",
			filename: empty,
		},
		{
			name:      "missing file",
			filename:  filename + ".missing",
			wantError: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := GetSecret(tc.plaintext, tc.filename)
			if tc.wantError {
				require.ErrorIs(t, err, os.ErrNotExist)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
