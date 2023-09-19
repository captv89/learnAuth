package main

import (
	"fmt"
	"github.com/go-chi/jwtauth/v5"
	"github.com/go-chi/render"
	"github.com/google/uuid"
	"gorm.io/gorm"
	"log"
	"net/http"
	"time"
)

// Implement Handler functions for the following endpoints:

// POST /register
func registerHandler(w http.ResponseWriter, r *http.Request) {
	// Parse username and password from request body
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Check and Validate username and password
	if username == "" || password == "" {
		// Send error back to client
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Encrypt password
	encryptedPassword := encryptPassword(password)

	// Create a new user
	user := User{Username: username, Password: encryptedPassword}

	// DB Create
	db, ok := r.Context().Value("DB").(*gorm.DB)
	if !ok {
		log.Println("Error: DB not found in context")
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Check if username already exists
	var count int64
	db.Model(&User{}).Where("username = ?", username).Count(&count)
	if count > 0 {
		log.Println("Error: Username already exists")
		// Send error back to client
		w.WriteHeader(http.StatusBadRequest)
		_, err := w.Write([]byte(`{"message": "Username already exists"}`))
		if err != nil {
			log.Println("Error: ", err)
			// Send error back to client
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	// Create user
	err := db.Create(&user).Error
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send success back to client
	w.WriteHeader(http.StatusOK)
}

// POST /login
func loginHandler(w http.ResponseWriter, r *http.Request) {
	// Parse username and password from request body
	username := r.FormValue("username")
	password := r.FormValue("password")

	log.Printf("U: %s and P: %s\n", username, password)

	// Check and Validate username and password
	if username == "" || password == "" {
		// Send error back to client
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Find user by username
	user := User{}
	db, ok := r.Context().Value("DB").(*gorm.DB)
	if !ok {
		log.Println("Error: DB not found in context")
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	err := db.Where("username = ?", username).First(&user).Error
	if err != nil {
		log.Println("Error: ", err)
		// User not found
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Print UserId and Username
	log.Printf("User ID: %d and Username: %s\n", user.ID, user.Username)

	// If user not found send error back to client
	if user.ID == 0 {
		// Send error back to client
		log.Println("User not found")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Decrypt password
	decryptedPassword := decryptPassword(user.Password)

	// Check if password is correct
	if password != decryptedPassword {
		// Send error back to client
		log.Println("Password is incorrect")
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// If authorised pass back a jwt token
	token, err := createToken(username)
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Create a new session
	session := &Session{UserID: user.ID, SessionID: uuid.New(), Token: token, Expiry: time.Now().Add(time.Hour * 24)}

	// Write session to database
	err = db.Create(&session).Error
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send success back to client with session cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "session_id",
		Value:   session.SessionID.String(),
		Expires: session.Expiry,
	})

	// Send success back to client with jwt token
	w.Header().Set("Content-Type", "application/json")
	_, err = w.Write([]byte(`{"token": "` + token + `"}`))
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

// POST /logout
func logoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session from the context
	session, ok := r.Context().Value("session").(*Session)
	if !ok {
		log.Println("Error: Session not found in context")
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	//Session ID
	sessionID := session.SessionID

	// Delete session from the database
	db, ok := r.Context().Value("DB").(*gorm.DB)
	if !ok {
		log.Println("Error: DB not found in context")
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err := db.Where("session_id = ?", sessionID).Delete(&Session{}).Error
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Send success back to client
	w.WriteHeader(http.StatusOK)
}

func homeHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte("Home Anonymous"))
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
	}
}

func protectedHandler(w http.ResponseWriter, r *http.Request) {
	// Get the username from the jwt token

	_, claims, err := jwtauth.FromContext(r.Context())
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
	}

	username, ok := claims["sub"].(string)
	if !ok {
		// Handle the case where "sub" is not a string (unexpected)
		log.Println("Error: Subject claim is not a string")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	_, err = w.Write([]byte(fmt.Sprintf("This is a protected area. Hi %v", username)))
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
	}
}

// ProtectedSessionHandler function to handle protected session
func protectedSessionHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session from the context
	session, ok := r.Context().Value("session").(*Session)
	if !ok {
		log.Println("Error: Session not found in context")
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Get the username from database
	user := User{}
	db, ok := r.Context().Value("DB").(*gorm.DB)
	if !ok {
		log.Println("Error: DB not found in context")
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err := db.Where("id = ?", session.UserID).First(&user).Error
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Return back a json response with the username
	w.Header().Set("Content-Type", "application/json")
	render.JSON(w, r, map[string]interface{}{
		"message":  "This is a area protected by session based auth.",
		"session":  session.SessionID.String(),
		"username": user.Username,
	})
}

// NotFoundHandler function to handles any route not found
func notFoundHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	_, err := w.Write([]byte("Not Found, Implement me!"))
	if err != nil {
		log.Println("Error: ", err)
		// Send error back to client
		w.WriteHeader(http.StatusInternalServerError)
	}
}

//func testHandler(w http.ResponseWriter, r *http.Request) {
//	fmt.Fprintf(w, "Hi there, I love %s!", r.URL.Path[1:])
//}
