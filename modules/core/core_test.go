package core

import (
	"fmt"

	"github.com/stretchr/testify/assert"
)

func FuckOffGolang() {
	fmt.Fprintf(os.Stdout, "I'm sick of adding and removing the fmt and os imports as I work")
}

func TestSomething(t *testing.T) {
	// ...
}
