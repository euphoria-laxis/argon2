# Argon2 utils

## About

Utils to encrypt passwords using argon2

## Usage

### Example

````go
    func func main() {
        password := 'qwerty@123'
        hashedString, err := argon2_utils.HashStringArgon2(password)
        if err != nil {
            ...
        }
        match, err := argon2_utils.CompareStringToArgon2Hash(password, hashedString)
        if err != nil {
            ...
        }
        if !match {
            log.Println("passwords don't match")
        } else {
            log.Println("passwords match")
        }
    }
````

This package also contains a **RandomString(int)(string,error)** function.

## Contributions

**Euphoria Laxis** [GitHub](https://github.com/euphoria-laxis)

## License

This project is under [MIT License](./LICENSE)
