package jwtaccess

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Secret key (nanti pas di service lain, ini harus sama persis)
// Di produksi, sebaiknya ambil dari environment variable, jangan hardcode
var jwtSecret = []byte("super-secret-key-minisoccer-ganti-ini-di-prod")

// Claims adalah struct data yang bakal diselipin ke dalam token
type Claims struct {
	UserID string `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

// GenerateToken membuat token JWT baru yang isinya UserID dan Role
func GenerateToken(userID string, role string, duration time.Duration) (string, error) {
	// Set waktu expired
	expirationTime := time.Now().Add(duration)

	// Bikin claims
	claims := &Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	// Bikin token dengan metode HS256
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Tanda tangani token pakai secret
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateToken mengecek apakah token valid dan mengembalikan Claims-nya
func ValidateToken(tokenString string) (*Claims, error) {
	claims := &Claims{}

	// Parse token
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		// Pastikan metode signing-nya sesuai (HS256)
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("metode signing tidak valid")
		}
		return jwtSecret, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("token tidak valid atau sudah expired")
	}

	return claims, nil
}
