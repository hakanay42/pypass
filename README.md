# PyPass - Password Manager

My Course Project 1 for Information Systems.

## What is this?

A simple password manager that runs on your computer.
All passwords are encrypted with AES-256 so even if someone
gets the file, they cannot read anything without the master password.

## How it works

1. You choose a master password when you first run it
2. Your passwords are encrypted and saved in a local file
3. Only the correct master password can decrypt them

## Encryption used

- AES-256-CBC for encrypting passwords
- PBKDF2-HMAC-SHA256 for key derivation (310,000 iterations)
- HMAC-SHA256 for file integrity check

## How to run
