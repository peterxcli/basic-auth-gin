package types

type ErrorResponse struct {
	Message string `json:"message"`
}

type ErrorResponseInvalidToken struct {
	Message string `json:"message"`
	Token   Token  `json:"token"`
}
