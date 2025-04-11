package main

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_newHandler(t *testing.T) {
	tests := map[string]struct {
		req request
		res *response
	}{
		"Valid Integer Summer": {
			req: request{X: 2, Y: 3},
			res: &response{Result: 5},
		},
		"Valid Float Summer": {
			req: request{X: 2.5, Y: 10.6},
			res: &response{Result: 13.1},
		},
		"Valid Negative Integer Summer": {
			req: request{X: -12, Y: -30},
			res: &response{Result: -42},
		},
		"Valid Negative Float Summer": {
			req: request{X: -30.1, Y: -101.6},
			res: &response{Result: -131.7},
		},
		"Invalid Summer ( X greater than maxX )": {
			req: request{X: 200, Y: 0},
			res: &response{Error: &responseError{Code: "InvalidRequest", Message: fmt.Sprintf("x must be less than %f", float64(100))}},
		},
		"Invalid Summer ( X less than minX )": {
			req: request{X: -76, Y: 0},
			res: &response{Error: &responseError{Code: "InvalidRequest", Message: fmt.Sprintf("x must be greater than %f", float64(-75))}},
		},
		"Invalid Summer ( Y greater than maxY )": {
			req: request{X: 0, Y: 43},
			res: &response{Error: &responseError{Code: "InvalidRequest", Message: fmt.Sprintf("y must be less than %f", float64(42))}},
		},
		"Invalid Summer ( Y less than minY )": {
			req: request{X: 0, Y: -1029},
			res: &response{Error: &responseError{Code: "InvalidRequest", Message: fmt.Sprintf("y must be greater than %f", float64(-1028))}},
		},
	}
	for name, test := range tests {
		name, test := name, test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			handler := newHandler(func(_ context.Context, x, y float64) float64 { return x + y })

			res, err := handler(context.Background(), test.req)
			assert.NoError(t, err)
			assert.Equal(t, res, test.res)
		})
	}
}
