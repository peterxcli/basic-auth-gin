package types

import (
	"encoding/json"

	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// UserType ...
type UserType struct{}

type User struct {
	Id              primitive.ObjectID `bson:"_id" json:"id,omitempty"`
	Email           string             `bson:"email" json:"email" validate:"required"`
	Password        string             `bson:"password" json:"password,omitempty"`
	Name            string             `bson:"name" json:"name" validate:"required"`
	EmailConfirmed  bool               `bson:"emailConfirmed" json:"emailConfirmed,omitempty"`
	EmailToken      string             `bson:"emailToken" json:"emailToken,omitempty"`
	PermissionLevel int                `bson:"permissionLevel" json:"permissionLevel"`
	ExternalType    string             `bson:"externalType" json:"externalType"`
	ExternalId      string             `bson:"externalId" json:"externalId"`
}

type UserNoId struct {
	Email           string `bson:"email" json:"email" validate:"required"`
	Password        string `bson:"password" json:"password,omitempty"`
	Name            string `bson:"name" json:"name" validate:"required"`
	EmailConfirmed  bool   `bson:"emailConfirmed" json:"emailConfirmed,omitempty"`
	EmailToken      string `bson:"emailToken" json:"emailToken,omitempty"`
	PermissionLevel int    `bson:"permissionLevel" json:"permissionLevel"`
	ExternalType    string `bson:"externalType" json:"externalType"`
	ExternalId      string `bson:"externalId" json:"externalId"`
}

// LoginType ...
type LoginType struct {
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" json:"password" binding:"required,min=3,max=50"`
}

// RegisterType ...
type RegisterType struct {
	Name     string `form:"name" json:"name" binding:"required,min=3,max=20,fullName"` //fullName rule is in validator.go
	Email    string `form:"email" json:"email" binding:"required,email"`
	Password string `form:"password" json:"password" binding:"required,min=3,max=50"`
}

type RegisterResponseType struct {
	Message string `form:"message" json:"message"`
	User    User   `form:"user" json:"user"`
}

type UserTokenAuthResponseType struct {
	Message string `form:"message" json:"message"`
	User    User   `form:"user" json:"user"`
}

type UserInfoWithOAuth struct {
	ExternalType string `bson:"externalType" json:"externalType"`
	ExternalId   string `bson:"externalId" json:"externalId"`
}

type LoginResponseType struct {
	Message string `form:"message" json:"message"`
	User    User   `form:"user" json:"user"`
	Token   Token  `form:"token" json:"token"`
}

// type RegisterResponseType struct {
// 	Message string `form:"message" json:"message"`
// 	User    User   `form:"user" json:"user"`
// 	Token   Token  `form:"token" json:"token"`
// }

// Name ...
func (f UserType) Name(tag string, errMsg ...string) (message string) {
	switch tag {
	case "required":
		if len(errMsg) == 0 {
			return "Please enter your name"
		}
		return errMsg[0]
	case "min", "max":
		return "Your name should be between 3 to 20 characters"
	case "fullName":
		return "Name should not include any special characters or numbers"
	default:
		return "Something went wrong, please try again later"
	}
}

// Email ...
func (f UserType) Email(tag string, errMsg ...string) (message string) {
	switch tag {
	case "required":
		if len(errMsg) == 0 {
			return "Please enter your email"
		}
		return errMsg[0]
	case "min", "max", "email":
		return "Please enter a valid email"
	default:
		return "Something went wrong, please try again later"
	}
}

// Password ...
func (f UserType) Password(tag string) (message string) {
	switch tag {
	case "required":
		return "Please enter your password"
	case "min", "max":
		return "Your password should be between 3 and 50 characters"
	case "eqfield":
		return "Your passwords does not match"
	default:
		return "Something went wrong, please try again later"
	}
}

// Login Signin ...
func (f UserType) Login(err error) string {
	switch err.(type) {
	case validator.ValidationErrors:

		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return "Something went wrong, please try again later"
		}

		for _, err := range err.(validator.ValidationErrors) {
			if err.Field() == "Email" {
				return f.Email(err.Tag())
			}
			if err.Field() == "Password" {
				return f.Password(err.Tag())
			}
		}

	default:
		return "Invalid request"
	}

	return "Something went wrong, please try again later"
}

// Register ...
func (f UserType) Register(err error) string {
	switch err.(type) {
	case validator.ValidationErrors:

		if _, ok := err.(*json.UnmarshalTypeError); ok {
			return "Something went wrong, please try again later"
		}

		for _, err := range err.(validator.ValidationErrors) {
			if err.Field() == "Name" {
				return f.Name(err.Tag())
			}

			if err.Field() == "Email" {
				return f.Email(err.Tag())
			}

			if err.Field() == "Password" {
				return f.Password(err.Tag())
			}

		}
	default:
		return "Invalid request"
	}

	return "Something went wrong, please try again later"
}
