package x11

import (
	"crypto/sha512"
	"github.com/samli88/go-x11-hash/aes"
	"github.com/samli88/go-x11-hash/blake"
	"github.com/samli88/go-x11-hash/bmw"
	"github.com/samli88/go-x11-hash/cubehash"
	"github.com/samli88/go-x11-hash/echo"
	"github.com/samli88/go-x11-hash/fugue"
	"github.com/samli88/go-x11-hash/groestl"
	"github.com/samli88/go-x11-hash/hamsi"
	"github.com/samli88/go-x11-hash/hash"
	"github.com/samli88/go-x11-hash/jh"
	"github.com/samli88/go-x11-hash/keccak"
	"github.com/samli88/go-x11-hash/luffa"
	"github.com/samli88/go-x11-hash/shabal"
	"github.com/samli88/go-x11-hash/shavite"
	"github.com/samli88/go-x11-hash/simd"
	"github.com/samli88/go-x11-hash/skein"
	"github.com/samli88/go-x11-hash/whirlpool"
)

const (
	BLAKE = iota
	BMW
	GROESTL
	JH
	KECCAK
	SKEIN
	LUFFA
	CUBEHASH
	SHAVITE
	SIMD
	ECHO
	HAMSI
	FUGUE
	SHABAL
	WHIRLPOOL
	SHA512
	HASH_FUNC_COUNT
)

var x16rv3_hashOrder = [HASH_FUNC_COUNT]uint{}

func aes_expand_key_soft(header []byte) [12]Uint128 {
	var keyData = make([]byte, 192)
	copy(keyData[:96], header[:96])
	var key = [12]Uint128{}
	for i := 0; i < 12; i++ {
		key[i] = FromBytes(keyData[i*16 : i*16+16])
	}
	key[6] = Xor128(key[0], key[2])
	key[7] = Xor128(key[1], key[3])
	key[8] = Xor128(key[0], key[4])
	key[9] = Xor128(key[1], key[5])
	key[10] = Xor128(key[2], key[4])
	key[11] = Xor128(key[3], key[5])
	return key
}

func get_x16rv3_order(input []byte) []byte {
	var ek [12]Uint128
	var endiandata [128]byte
	copy(endiandata[:113], input[:113])
	ek = aes_expand_key_soft(input[4:])
	var aesdata = [12]Uint128{}
	var data_in [8]Uint128
	for i := 0; i < 8; i++ {
		data_in[i] = FromBytes(endiandata[i*16 : i*16+16])
	}
	for j := 0; j < 8; j++ {
		aesdata[j] = FromIntsArray(aes.Aes_enc_soft(aesdata[j].ToUint64(), data_in[j].ToUint64(), ek[j].ToUint64()))
	}
	var xor_out Uint128
	xor_out = Ur128_5xor(aesdata[4], aesdata[5], aesdata[6], aesdata[7], aesdata[0])
	aesdata[8] = FromIntsArray(aes.Aes_enc_soft(aesdata[8].ToUint64(), xor_out.ToUint64(), ek[8].ToUint64()))
	xor_out = Ur128_5xor(aesdata[4], aesdata[5], aesdata[6], aesdata[7], aesdata[1])
	aesdata[9] = FromIntsArray(aes.Aes_enc_soft(aesdata[9].ToUint64(), xor_out.ToUint64(), ek[9].ToUint64()))
	xor_out = Ur128_5xor(aesdata[4], aesdata[5], aesdata[6], aesdata[7], aesdata[2])
	aesdata[10] = FromIntsArray(aes.Aes_enc_soft(aesdata[10].ToUint64(), xor_out.ToUint64(), ek[10].ToUint64()))
	xor_out = Ur128_5xor(aesdata[4], aesdata[5], aesdata[6], aesdata[7], aesdata[3])
	aesdata[11] = FromIntsArray(aes.Aes_enc_soft(aesdata[11].ToUint64(), xor_out.ToUint64(), ek[11].ToUint64()))
	outPut := ArrayToBytes(aesdata[8:])
	aesData6 := aesdata[6].GetBytes()
	for k := 0; k < 16; k++ {
		x16rv3_hashOrder[k] = uint(aesData6[k] & 0x0f)
	}
	return outPut
}

// Hash contains the state objects
// required to perform the x11.Hash.
type Hash struct {
	tha [64]byte
	thb [64]byte

	blake    hash.Digest
	bmw      hash.Digest
	cubehash hash.Digest
	echo     hash.Digest
	groestl  hash.Digest
	jh       hash.Digest
	keccak   hash.Digest
	luffa    hash.Digest
	shavite  hash.Digest
	simd     hash.Digest
	skein    hash.Digest
}

// New returns a new object to compute a x11 hash.
func New() *Hash {
	ref := &Hash{}

	ref.blake = blake.New()
	ref.bmw = bmw.New()
	ref.cubehash = cubehash.New()
	ref.echo = echo.New()
	ref.groestl = groestl.New()
	ref.jh = jh.New()
	ref.keccak = keccak.New()
	ref.luffa = luffa.New()
	ref.shavite = shavite.New()
	ref.simd = simd.New()
	ref.skein = skein.New()

	return ref
}

// Hash computes the hash from the src bytes and stores the result in dst.
func (ref *Hash) Hash(src []byte, dst []byte) {
	outHash := get_x16rv3_order(src)
	in := ref.tha[:]
	copy(in[:], outHash[:])
	out := ref.thb[:]
	for i := 0; i < 16; i++ {
		switch x16rv3_hashOrder[i] {
		case BLAKE:
			ref.blake.Write(in)
			ref.blake.Close(out, 0, 0)
			copy(in, out)
			break
		case BMW:
			ref.bmw.Write(in)
			ref.bmw.Close(out, 0, 0)
			copy(in, out)
			break
		case GROESTL:
			ref.groestl.Write(in)
			ref.groestl.Close(out, 0, 0)
			copy(in, out)
			break
		case SKEIN:
			ref.skein.Write(in)
			ref.skein.Close(out, 0, 0)
			copy(in, out)
			break
		case JH:
			ref.jh.Write(in)
			ref.jh.Close(out, 0, 0)
			copy(in, out)
			break
		case KECCAK:
			ref.keccak.Write(in)
			ref.keccak.Close(out, 0, 0)
			copy(in, out)
			break
		case LUFFA:
			ref.luffa.Write(in)
			ref.luffa.Close(out, 0, 0)
			copy(in, out)
			break
		case CUBEHASH:
			ref.cubehash.Write(in)
			ref.cubehash.Close(out, 0, 0)
			copy(in, out)
			break
		case SHAVITE:
			ref.shavite.Write(in)
			ref.shavite.Close(out, 0, 0)
			copy(in, out)
			break
		case SIMD:
			ref.simd.Write(in)
			ref.simd.Close(out, 0, 0)
			copy(in, out)
			break
		case ECHO:
			ref.echo.Write(in)
			ref.echo.Close(out, 0, 0)
			copy(in, out)
			break
		case HAMSI:
			hamsi.Sph_hamsi512_process(in[:], out[:], 64)
			copy(in, out)
			break
		case FUGUE:
			fugue.Sph_fugue512_process(in[:], out[:], 64)
			copy(in, out)
			in = out
			break
		case SHABAL:
			shabal.Shabal_512_process(in[:], out[:], 64)
			copy(in, out)
			break
		case WHIRLPOOL:
			wh := whirlpool.New()
			wh.Write(in)
			out = wh.Sum(nil)
			copy(in, out)
			break
		case SHA512:
			sha := sha512.New()
			sha.Write(in)
			out = sha.Sum(nil)
			copy(in, out)
			break
		}
	}
	copy(dst, in[:32])
}
