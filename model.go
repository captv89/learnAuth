package main

import "gorm.io/gorm"

// Define data structures for the following:

// User struct
type User struct {
	gorm.Model
	Username string `gorm:"unique_index;not null"`
	Password string `gorm:"not null"`
}

func (u User) validate() error {
	return nil
}

func (u User) insert() error {
	return nil
}
