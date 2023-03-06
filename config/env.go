package config

import (
	"log"
	"os"
	"reflect"

	"github.com/joho/godotenv"
)

// EnvVarDetails ...
type EnvVarDetails struct {
	MONGOURI             string
	REDIS_HOST           string
	REDIS_PASSWORD       string
	ACCESS_SECRET        string
	REFRESH_SECRET       string
	GOOGLE_CLIENT_ID     string
	GOOGLE_CLIENT_SECRET string
	REDIRECT_URI         string
	FRONTEND_URI         string
	SENDGRID_API_KEY     string
	EMAIL_CONFIRM_URI    string
	EMAIL                string
	ENV                  string
	PORT                 string
	SSL                  string
	API_VERSION          string
}

func NewEnvVarDetails() *EnvVarDetails {

	// set default value of env variable
	envVarDetails := &EnvVarDetails{}
	envVarDetails.EMAIL_CONFIRM_URI = "http://localhost:9000/v1/user/verify_email?token="
	envVarDetails.MONGOURI = "mongodb://localhost:27017"
	envVarDetails.ACCESS_SECRET = "1234"
	envVarDetails.REFRESH_SECRET = "5678"
	envVarDetails.ENV = "LOCAL"
	envVarDetails.PORT = "9000"
	envVarDetails.SSL = "FALSE"
	envVarDetails.API_VERSION = "1.0"

	return envVarDetails
}

var Env *EnvVarDetails = envInit()

func envInit() *EnvVarDetails {
	err := godotenv.Load()
	if err != nil {
		log.Println("\033[37;101mError loading .env file\033[0m")
	}
	_env := NewEnvVarDetails()

	// Get the type of the EnvVarDetails struct
	envType := reflect.TypeOf(*_env)

	// Iterate over all fields of the EnvVarDetails struct
	for i := 0; i < envType.NumField(); i++ {
		field := envType.Field(i)

		// Get the value of the environment variable with the same name as the field
		value := os.Getenv(field.Name)

		// If the environment variable is set, assign its value to the field in the env variable
		if value != "" {
			reflect.ValueOf(_env).Elem().FieldByName(field.Name).SetString(value)
		}
	}
	return _env
}
