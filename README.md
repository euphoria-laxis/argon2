# Argon2 utils

## About

Utils simplify passwords hashing using argon2

## Usages

### Basic usage example

````go
package main

import "github.com/euphoria-laxis/argon2/hashing"

func main() 
    password := "qwerty@123
    // Create new encoder using default 
    hasher := hashing.NewHasher()
    hashedString, err := hasher.HashString(password)
    if err != nil {
        // handle error
        panic(err)
    }
    match, err := hasher.CompareStringToHash(password, hashedString)
    if err != nil {
        // handle error
        panic(err)
    }
    if !match {
        // password doesn't march
        panic("password and hash do not match")
    }
    print("success")
}
````

### Configure hasher options

````go
// Create new encoder using custom parameters
hasher := hashing.NewHasher(
    hashing.SetMemory(64 * 1024),
    hashing.SetParallelism(4),
    hashing.SetKeyLength(32),
    hashing.SetSaltLength(32),
    hashing.SetIterations(4),
)
````

You can use the [example](./_examples/example.go) to see the package usage.

## Contributions

**Euphoria Laxis** [GitHub](https://github.com/euphoria-laxis)

## License

This project is under [MIT License](./LICENSE)
