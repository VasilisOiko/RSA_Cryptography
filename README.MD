# RSA Encryption and Signature

## Description

This project was part of [Information Technology Security](http://www.ice.uniwa.gr/en/education-1/undergraduate/courses/information-technology-security/) cource.

The learning objective of this exercise is the RSA cryptographic algorithm. Using the seedLabs VM image [Ubuntu 16.04](https://seedsecuritylabs.org/labsetup.html)

Eexercise objectives:
- Generate private key
- Encrypt a message using the private key
- Decrypt the Message
- Attach a digital signature to a message
- Verification of digital singature
- Certificate verification

## Installation
- SeedLab Ubuntu 16.04 VM
- [OpenSSL bn](https://www.openssl.org/docs/man1.0.2/man3/bn.html) (multiprecision integer arithmetics) library
- C compiler

_SeedLab VM image include the GCC compiler and OpenSSL library_

## Usage
The exercise.sh script compile and runs the exercise_1.c program.

The script has an optional argument. The argument is used as the message.

```bash
    # Execute the script (default message: Oikonomoy Vasileios)
    ./exercise_1.sh

    # set message
    ./exercise_1.sh message
```