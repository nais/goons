package main

import (
	"context"

	goons "github.com/nais/goons/internal/cmd"
)

func main() {
	ctx := context.Background()
	goons.Run(ctx)
}
