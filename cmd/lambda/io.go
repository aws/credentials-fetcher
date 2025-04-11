package main

import "fmt"

// request represents the shape of the input to this lambda function.
type request struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// validate is used to verify that values of the request are acceptable.
// If not, an error is returned.
// The limits set in this function are arbitrary and exist to illustrate how one might do valid request validation.
func (r request) validate() error {
	if maxX := 100.0; r.X > maxX {
		return fmt.Errorf("x must be less than %f", maxX)
	}
	if minX := -75.0; r.X < minX {
		return fmt.Errorf("x must be greater than %f", minX)
	}
	if maxY := 42.0; r.Y > maxY {
		return fmt.Errorf("y must be less than %f", maxY)
	}
	if minY := -1028.0; r.Y < minY {
		return fmt.Errorf("y must be greater than %f", minY)
	}
	return nil
}

// response represents the shape of the output of this lambda function.
type response struct {
	Error  *responseError `json:"error,omitempty"`
	Result float64        `json:"result,omitempty"`
}

// responseError represents the shape of the error output of this lambda function.
type responseError struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}
