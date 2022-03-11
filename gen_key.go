package main

import (
    "os"
    "crypto/rand"
    "encoding/base64"
)

func main() {
    f, _ := os.Create("session_key.env")
    key := make([]byte, 32)
    rand.Read(key)
    f.WriteString(base64.StdEncoding.EncodeToString(key))
    f.Close()
}
