package main

import (
	"github.com/google/uuid"
	"gorm.io/gorm"
	"time"
)

// Define data structures for the following:

// User struct
type User struct {
	gorm.Model
	Username string `gorm:"unique_index;not null"`
	Password string `gorm:"not null"`
}

// Session struct
type Session struct {
	gorm.Model
	UserID    uint      `gorm:"not null"`
	Token     string    `gorm:"unique_index;not null"`
	SessionID uuid.UUID `gorm:"unique_index;not null"`
	Expiry    time.Time `gorm:"not null"`
}
