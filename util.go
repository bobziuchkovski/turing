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

package turing

func getOctet(word uint32, n uint) byte {
	return byte((word >> (24 - n*8)) & 0xff)
}

func splitWord(word uint32) []byte {
	var octets [4]byte
	octets[0] = byte((word >> 24) & 0xff)
	octets[1] = byte((word >> 16) & 0xff)
	octets[2] = byte((word >> 8) & 0xff)
	octets[3] = byte(word & 0xff)
	return octets[:]
}

func joinWord(octets [4]byte) uint32 {
	return (uint32(octets[0]) << 24) | (uint32(octets[1]) << 16) | (uint32(octets[2]) << 8) | uint32(octets[3])
}

func rotl(word uint32, shift uint) uint32 {
	return (word << shift) | (word >> (32 - shift))
}

func rotr(word uint32, shift uint) uint32 {
	return (word >> shift) | (word << (32 - shift))
}
