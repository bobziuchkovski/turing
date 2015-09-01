// Copyright (c) 2016 Bob Ziuchkovski
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

// Package turing implements the Turing stream cipher, as defined in
// Gregory G. Rose and Philip Hawkes "Turing: a Fast Stream Cipher".
// The package API mimics that of the crypto/rc4 package.
package turing

import (
	"fmt"
)

const reglen = 17
const minkey = 8
const maxkey = 32
const maxiv = 48
const confounder = 0x1020300

// KeySizeError is used to indicate problems with provided key/IV values.
// See the NewCipher for key/IV requirements.
type KeySizeError string

func (k KeySizeError) Error() string {
	return "turing: " + string(k)
}

// Cipher is an instance of the Turing cipher using a particular key/IV pair
type Cipher struct {
	key    []uint32
	keybox [4][256]uint32
	reg    [reglen]uint32
	buffer [20]byte
	bufpos int
}

// NewCipher creates and returns a new Cipher.  The key size must be a multiple
// of 4 bytes and must be between 8 and 32 bytes.  The IV is optional and may
// be omitted by specifying a nil value.  If the IV is present, the size must
// be a multiple of 4 bytes.  The combined size of the key and IV must not
// exceed 48 bytes.  These restrictions are part of the algorithm specs.
func NewCipher(key []byte, iv []byte) (cipher *Cipher, err error) {
	keylen := len(key)
	ivlen := len(iv)

	if keylen%4 != 0 {
		return nil, KeySizeError("key size must be a multiple of 4")
	}
	if ivlen%4 != 0 {
		return nil, KeySizeError("iv size must be a multiple of 4")
	}
	if keylen < minkey {
		return nil, KeySizeError(fmt.Sprintf("key size must be >= %d", minkey))
	}
	if keylen > maxkey {
		return nil, KeySizeError(fmt.Sprintf("key size must be <= %d", maxkey))
	}
	if keylen+ivlen > maxiv {
		return nil, KeySizeError(fmt.Sprintf("combined key and iv sizes must be <= %d", maxiv))
	}

	cipher = &Cipher{}
	cipher.initKey(key)
	cipher.initIV(iv)
	cipher.nextRound()
	return
}

// Reset makes a best effort attempt to remove the key data from memory.
// However, go's garbage-collecting semantics make it impossible to provide
// an absolute guarantee that the key data is completely unreachable.
func (cipher *Cipher) Reset() {
	for i := range cipher.key {
		cipher.key[i] = 0
	}
	for i := range cipher.keybox {
		for j := range cipher.keybox[i] {
			cipher.keybox[i][j] = 0
		}
	}
	for i := range cipher.buffer {
		cipher.buffer[i] = 0
	}
	for i := range cipher.reg {
		cipher.reg[i] = 0
	}
	cipher.bufpos = 0
}

// XORKeyStream sets dst to the result of XORing src with the key stream.
// Dst and src may be the same slice but otherwise should not overlap.
func (cipher *Cipher) XORKeyStream(dst, src []byte) {
	for i := range src {
		if cipher.bufpos == len(cipher.buffer) {
			cipher.nextRound()
		}
		dst[i] = src[i] ^ cipher.buffer[cipher.bufpos]
		cipher.bufpos++
	}
}

func (cipher *Cipher) nextRound() {
	cipher.clockRegister()
	a, b, c, d, e := cipher.reg[16], cipher.reg[13], cipher.reg[6], cipher.reg[1], cipher.reg[0]

	// Non-linear filter
	e += a + b + c + d
	a, b, c, d = a+e, b+e, c+e, d+e
	a, b, c, d, e = cipher.keyedS(a, 0), cipher.keyedS(b, 8), cipher.keyedS(c, 16), cipher.keyedS(d, 24), cipher.keyedS(e, 0)
	e += a + b + c + d
	a, b, c, d = a+e, b+e, c+e, d+e

	cipher.clockRegister()
	cipher.clockRegister()
	cipher.clockRegister()

	a, b, c, d, e = a+cipher.reg[14], b+cipher.reg[12], c+cipher.reg[8], d+cipher.reg[1], e+cipher.reg[0]
	copy(cipher.buffer[0:4], splitWord(a))
	copy(cipher.buffer[4:8], splitWord(b))
	copy(cipher.buffer[8:12], splitWord(c))
	copy(cipher.buffer[12:16], splitWord(d))
	copy(cipher.buffer[16:20], splitWord(e))
	cipher.bufpos = 0

	cipher.clockRegister()
}

func (cipher *Cipher) clockRegister() {
	word := cipher.reg[15] ^ cipher.reg[4] ^ (cipher.reg[0] << 8) ^ mtab[cipher.reg[0]>>24]
	for i := 0; i < reglen-1; i++ {
		cipher.reg[i] = cipher.reg[i+1]
	}
	cipher.reg[reglen-1] = word
}

// We use the pre-calculated keyed sbox approach outlined in "Turing: a Fast Stream Cipher"
func (cipher *Cipher) keyedS(word uint32, rotate uint) uint32 {
	var s uint32
	for i, octet := range splitWord(rotl(word, rotate)) {
		s ^= cipher.keybox[i][octet]
	}
	return s
}

func (cipher *Cipher) initKey(key []byte) {
	cipher.key = make([]uint32, len(key)/4)
	for i := range cipher.key {
		quad := [4]byte{key[i*4], key[i*4+1], key[i*4+2], key[i*4+3]}
		cipher.key[i] = fixedS(joinWord(quad))
	}
	hadamard(cipher.key)

	// Pre-calculate keyed sboxes
	for box := range cipher.keybox {
		for i := range sbox {
			var (
				shift = uint(box * 8)
				octet = byte(i)
				word  uint32
			)
			for keypos, key := range cipher.key {
				octet = sbox[getOctet(key, uint(box))^octet]
				word ^= rotl(qbox[octet], uint(keypos)+shift)
			}
			cipher.keybox[box][i] = (word & rotr(0x00ffffff, shift)) | (uint32(octet) << (24 - shift))
		}
	}
}

func (cipher *Cipher) initIV(iv []byte) {
	r := 0
	for i := 0; i < len(iv)/4; i++ {
		quad := [4]byte{iv[i*4], iv[i*4+1], iv[i*4+2], iv[i*4+3]}
		cipher.reg[r] = fixedS(joinWord(quad))
		r++
	}

	for _, k := range cipher.key {
		cipher.reg[r] = k
		r++
	}

	cipher.reg[r] = uint32(confounder | (len(cipher.key) << 4) | len(iv)/4)
	r++

	for i := 0; r < reglen; i++ {
		cipher.reg[r] = cipher.keyedS(cipher.reg[i]+cipher.reg[r-1], 0)
		r++
	}

	hadamard(cipher.reg[:])
}

func fixedS(word uint32) uint32 {
	var i uint
	for i = 0; i < 4; i++ {
		shift := i * 8
		octet := sbox[getOctet(word, i)]
		word = ((word ^ rotl(qbox[octet], shift)) & rotr(0x00ffffff, shift)) | (uint32(octet) << (24 - shift))
	}
	return word
}

// pseudo-hadamard transform
func hadamard(words []uint32) {
	var sum uint32
	for _, w := range words {
		sum += w
	}
	words[len(words)-1] = 0
	for i := range words {
		words[i] += sum
	}
}
