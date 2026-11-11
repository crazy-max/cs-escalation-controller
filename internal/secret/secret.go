package secret

import "os"

// GetSecret returns plaintext when set, otherwise the file's unmodified contents.
func GetSecret(plaintext, filename string) (string, error) {
	if plaintext != "" {
		return plaintext, nil
	}
	if filename != "" {
		data, err := os.ReadFile(filename)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return "", nil
}
