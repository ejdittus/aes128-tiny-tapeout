<!---

This file is used to generate your project datasheet. Please fill in the information below and delete any unused
sections.

You can also include images in this folder and reference them in the markdown. Each image must be less than
512 kb in size, and the combined size of all images must be less than 1 MB.
-->

# AES-128 Encryption

## How it works

This project implements an iterative AES-128 encryption core.
It accepts a 128-bit key and a 128-bit plaintext, processes
the AES encryption rounds, and produces a 128-bit ciphertext.

The Tiny Tapeout interface transfers key and plaintext data
one byte at a time using the 8-bit ui_in input. The uio_in
pins select the operation.

Commands:
- 0x01: Load one key byte.
- 0x02: Load one plaintext byte.
- 0x03: Start encryption.
- 0x04: Read one ciphertext byte.
- 0x05: Read status; bit 0 indicates busy and bit 1 indicates done.

Key and plaintext bytes are loaded most-significant byte first.
Ciphertext bytes are read most-significant byte first.

## How to test

1. Assert reset using rst_n.
2. Send command 0x01 and load all 16 key bytes.
3. Send command 0x02 and load all 16 plaintext bytes.
4. Send command 0x03 to start encryption.
5. Poll status using command 0x05 until the done bit is set.
6. Read the 16 ciphertext bytes using command 0x04.
7. Compare the result against a known AES-128 test vector.

A recommended test vector is:

Key:
000102030405060708090a0b0c0d0e0f

Plaintext:
00112233445566778899aabbccddeeff

Expected ciphertext:
69c4e0d86a7b0430d8cdb78070b4c55a

## External hardware

No external hardware is required for simulation. The design
uses the clock and reset signals provided by Tiny Tapeout.
