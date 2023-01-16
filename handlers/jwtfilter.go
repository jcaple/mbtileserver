package handlers

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"github.com/golang-jwt/jwt"
)

// Thanks to: https://vikaspogu.dev/posts/sso-jwt-golang/

// HandlerWrapper is a type definition for a function that takes an http.Handler
// and returns an http.Handler
type HandlerWrapperJWT func(http.Handler) http.Handler

func JWTFilterMiddleware(secretKey string, cookieName string) HandlerWrapperJWT {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			
			rsaKey, _ := base64.StdEncoding.DecodeString(secretKey);

			//fmt.Printf("Cert: %s\n", rsaKey);
			
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				//fmt.Printf("Err: %s\n", err)
				http.Error(w, "No Token Presented", http.StatusUnauthorized)
				return
			}

			reqToken := cookie.Value

			//fmt.Printf("JWT: %s\n", reqToken);

			key, er := jwt.ParseRSAPublicKeyFromPEM([]byte(rsaKey))
			if er != nil {
				//fmt.Printf("RSAParser Error: %s\n", er)
				http.Error(w, "Certificate Error", http.StatusUnauthorized)
				return
			}

			token, err := jwt.Parse(reqToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
					return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
				}
				return key, nil
			})
	
			//if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if _, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				//fmt.Printf("%v", claims)
			} else {
				//fmt.Printf("Claims Err: %s\n", err)
				http.Error(w, "Invalid Token", http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}