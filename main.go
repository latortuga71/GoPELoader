package main

import (
	"log"
	"os"

	"github.com/latortuga71/GoPeLoader/pkg/peloader"
)

func main() {
	pePath := ``
	data, err := os.ReadFile(pePath)
	if err != nil {
		log.Fatal(err)
	}
	rawPeFile := peloader.NewRawPE(peloader.Dll, false, data)
	err = rawPeFile.LoadPEFromMemory()
	if err != nil {
		log.Fatal(err)
	}
	err = rawPeFile.FreePeFromMemory()
	if err != nil {
		log.Fatal(err)
	}
}
