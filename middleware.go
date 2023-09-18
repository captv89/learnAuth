package main

import (
	"context"
	"net/http"
	"time"
)

// SetDBMiddleware function to set the database middleware
func SetDBMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timeoutContext, _ := context.WithTimeout(context.Background(), time.Second)
		ctx := context.WithValue(r.Context(), "DB", db.WithContext(timeoutContext))
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// SetSessionMiddleware function to set the authentication middleware
func SetSessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve session id from the cookie
		sessionID, err := r.Cookie("session_id")
		if err != nil {
			// Send error back to client
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Retrieve session from the database
		session := &Session{}
		err = db.Where("session_id = ?", sessionID.Value).First(&session).Error
		if err != nil {
			// Send error back to client
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Check if session is expired
		if session.Expiry.Before(time.Now()) {
			// Send error back to client
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// Set session in context
		ctx := context.WithValue(r.Context(), "session", session)
		next.ServeHTTP(w, r.WithContext(ctx))
	})

}
