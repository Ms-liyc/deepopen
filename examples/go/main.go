package main

import (
        "crypto/tls"
        "fmt"
        "os/exec"
)

func main() {
        exec.Command("sh", "-c", "echo hi")
        _ = tls.Config{InsecureSkipVerify: true}
        query := fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", "x")
        fmt.Println(query)
}
