package main

import (
	"context"
	"errors"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/jwtauth/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// TODO:
// Implement a user authentication system that supports login, logout, and signup.
// The system should allow for multiple users to be logged in at once.
// The system should support multiple sessions per user.
// The system should support a way to expire sessions.
// The system should support a way to expire users.

// Global variables
var db *gorm.DB
var tokenAuth *jwtauth.JWTAuth

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	tokenAuth = jwtauth.New("HS256", []byte(SecretKey), nil)

	// For debugging/example purposes, we generate and print
	// a sample jwt token with claims `user_id:123` here:
	_, tokenString, err := tokenAuth.Encode(map[string]interface{}{"user_id": 123})
	if err != nil {
		log.Fatal("Error: ", err)
	}
	log.Printf("DEBUG: a sample jwt is %s\n\n", tokenString)
}

// Main function
func main() {
	// Initialize database
	initDB()
	run()
}

// InitDB function
func initDB() {
	var err error
	db, err = gorm.Open(sqlite.Open("auth.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	log.Println("Database connected")

	// Migrate:
	// Migrate the user schema
	err = db.AutoMigrate(&User{})
	if err != nil {
		log.Panicln("Error: ", err)
	}
	log.Println("Migrated User schema")

	// Migrate the session schema
	err = db.AutoMigrate(&Session{})
	if err != nil {
		log.Panicln("Error: ", err)
	}
	log.Println("Migrated Session schema")

	log.Println("Migrations completed")

}

// Run function
func run() {
	//Server:
	server := &http.Server{Addr: ":8080", Handler: apiServer()}

	// Server run context
	serverCtx, serverStopCtx := context.WithCancel(context.Background())

	// Listen for sys call to process interrupt/quit
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		s := <-sig
		log.Println("Got Signal:", s)

		// Shutdown signal with grace period of 30 seconds
		shutdownCtx, _ := context.WithTimeout(serverCtx, 30*time.Second)

		go func() {
			<-shutdownCtx.Done()
			if errors.Is(shutdownCtx.Err(), context.DeadlineExceeded) {
				log.Fatal("graceful shutdown timed out.. forcing exit.")
			}
		}()

		// Trigger graceful shutdown
		err := server.Shutdown(shutdownCtx)
		if err != nil {
			log.Fatal(err)
		}
		log.Println("Server shutdown gracefully")

		// Close the database connection gracefully
		if db != nil {
			dbConn, err := db.DB()
			if err != nil {
				log.Println("Error: ", err)
			}
			err = dbConn.Close()
			log.Println("Database connection closed.")
		}

		serverStopCtx()
	}()

	// Start Server: Listen on port 8080
	log.Println("Server starting on port 8080..")
	err := server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal("Error: ", err)
	}

	// Stop server
	// Wait for server context to be stopped
	<-serverCtx.Done()
}

// apiServer function returns a http.handler
func apiServer() http.Handler {
	//	Using mux router for routing register url path and handler
	router := chi.NewRouter()

	// Middlewares:
	//	Using middleware for logging
	router.Use(middleware.Logger)
	//	Using middleware for recovering from panics
	router.Use(middleware.Recoverer)
	// Using middleware for RealIP
	router.Use(middleware.RealIP)
	// Using middleware for RequestID
	router.Use(middleware.RequestID)
	// Using middleware for Timeout
	router.Use(middleware.Timeout(60 * time.Second))
	// Using middleware for Heartbeat
	router.Use(middleware.Heartbeat("/health"))
	// Using middleware for Compress
	router.Use(middleware.Compress(5, "gzip"))
	// Using middleware for CleanPath
	router.Use(middleware.CleanPath)
	// Using middleware for Charset
	router.Use(middleware.SetHeader("Content-Type", "application/json; charset=utf-8"))
	// Using middleware for DB context
	router.Use(SetDBMiddleware)

	// Routes:
	// Home
	router.Get("/", homeHandler)
	// Not Found
	router.NotFound(notFoundHandler)
	// Register
	router.Post("/register", registerHandler)
	// Login
	router.Post("/login", loginHandler)

	// JWT Protected routes:
	router.Group(func(r chi.Router) {
		// JWT middleware
		r.Use(jwtauth.Verifier(tokenAuth))
		r.Use(jwtauth.Authenticator)
		// JWT
		r.Get("/jwt", protectedHandler)
	})

	// Session Protected routes:
	router.Group(func(r chi.Router) {
		// Session middleware
		r.Use(SetSessionMiddleware)
		// Session
		r.Get("/session", protectedSessionHandler)
		// Logout
		r.Post("/logout", logoutHandler)
	})

	return router
}
