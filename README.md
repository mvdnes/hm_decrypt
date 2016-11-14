# hMailServer Password Decrypter

hMailServer has a configuration file which may contain encrypted credentials
for the database connection. The encryption used by hMailServer is a
[non-standard] blowfish implementation. This program is a portable equivalent
of this encryption method.

## Usage

    hmailserver_password.exe enc "PasswordToEncrypt"
    hmailserver_password.exe dec "b54084c9e4d331897a52d005a8a9e65d73930c0d8e4a90aa"

[non-standard]: https://www.hmailserver.com/forum/viewtopic.php?t=13842#p82038
