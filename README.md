# Argon2 utils

## About

Utils to encrypt passwords using argon2

## Usages

### Hash password

````go
    password := 'qwerty@123'
    // Create new encoder using default options
    encoder, _ := argon2.NewEncoder()
    hashedString, err = encoder.HashString(randomString)
    if err != nil {
        // handle error
    }
````

### Compare password with hashed string

````go
    // Create new decoder using default options
    decoder, _ := argon2.NewDecoder()
    match, err := decoder.CompareStringToHash(password, hashedString)
    if err != nil {
		// handle error
    }
````

### Configure encoder or decoder options

Note that encoder and decoder inherited from the same base struct *(argon2.Options)*.
You can use the same `argon2.OptFunc` slice to configure both encoder and decoder.

````go
    // Create new encoder using custom parameters
    encoder, options := argon2.NewEncoder(
        SetMemory(64 * 1024), // 64 bits
        SetParallelism(4),    // 4 concurrent actions
        SetKeyLength(32),     // key length
        SetSaltLength(32),    // salt length
        SetIterations(4),     // number of iterations
    )
````

## Contributions

**Euphoria Laxis** [GitHub](https://github.com/euphoria-laxis)

## License

This project is under [MIT License](./LICENSE)
