package ghaudit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const minKeyBits = 2048

// Client ID d'une App (Iv1.…, Iv23…) ou App ID numérique : l'un ou l'autre sert d'iss au JWT.
var reAppID = regexp.MustCompile(`^(?:[1-9][0-9]{0,11}|Iv[0-9A-Za-z.]{2,40})$`)

// ParseKey lit la clé privée de l'App, PEM PKCS#1 telle que GitHub la donne ou
// PKCS#8. Une variable saisie sur une ligne garde ses retours sous la forme \n.
// Aucune erreur ne cite la valeur.
func ParseKey(s string) (*rsa.PrivateKey, error) {
	s = strings.TrimSpace(s)
	if !strings.Contains(s, "\n") {
		s = strings.ReplaceAll(s, `\n`, "\n")
	}
	block, rest := pem.Decode([]byte(s))
	if block == nil {
		return nil, errors.New("clé de l'App : bloc PEM attendu")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("clé de l'App : un seul bloc PEM attendu")
	}
	if len(block.Headers) > 0 {
		return nil, errors.New("clé de l'App : PEM chiffré ou avec en-têtes refusé")
	}
	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("clé de l'App : PKCS#1 illisible")
		}
		key = k
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, errors.New("clé de l'App : PKCS#8 illisible")
		}
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("clé de l'App : clé RSA attendue")
		}
		key = rk
	default:
		return nil, errors.New("clé de l'App : RSA PRIVATE KEY ou PRIVATE KEY attendu")
	}
	if key.N.BitLen() < minKeyBits {
		return nil, errors.New("clé de l'App : 2048 bits au moins")
	}
	if err := key.Validate(); err != nil {
		return nil, errors.New("clé de l'App : clé RSA invalide")
	}
	return key, nil
}

// appJWT signe le JWT d'App en RS256. iat recule d'une minute contre l'écart
// d'horloge, exp reste sous les 10 minutes que GitHub accepte.
func appJWT(appID string, key *rsa.PrivateKey, now time.Time) (string, error) {
	var iss any = appID
	if n, err := strconv.ParseInt(appID, 10, 64); err == nil {
		iss = n
	}
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": iss,
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", errors.New("signature du JWT de l'App impossible")
	}
	return signing + "." + enc.EncodeToString(sig), nil
}
