// https://github.com/FreeRADIUS/freeradius-server/blob/9e5e8f2f912ad2da8ac6e176ac3a606333469937/src/modules/rlm_eap/types/rlm_eap_pwd/eap_pwd.c#L245
package pwd

import (
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/big"
	"unsafe"
)

const EAP_KEY = "EAP-pwd Hunting And Pecking"

type State struct {
	Token    uint32
	IDPeer   string
	IDServer string
	Password string

	X *big.Int
	Y *big.Int
}

func KDF(key []byte, label string, resultBitLen uint16) []byte {
	resultByteLen := (resultBitLen + 7) / 8
	// TODO: Correct instead of htons?
	mask := byte(0xff)
	L := make([]byte, 2)
	n := make([]byte, 2)
	binary.BigEndian.PutUint16(L[0:2], resultBitLen)
	mdlen := uint16(SHA256_DIGEST_LENGTH)

	output := make([]byte, resultByteLen)
	strlen := uint16(0)
	var digest []byte
	for i := uint16(1); i < 100; i++ {
		if strlen >= resultByteLen {
			break
		}

		// TODO: again instead of htons?
		binary.BigEndian.PutUint16(n[0:2], i)

		mac := hmac.New(sha256.New, key)
		if i > 0 {
			mac.Write(digest)
		}
		mac.Write(n)
		mac.Write([]byte(label))
		mac.Write(L)
		digest := mac.Sum(nil)
		digest = digest[0:]

		if (strlen + mdlen) > resultByteLen {
			copy(output[strlen:], digest[:resultByteLen-strlen])
		} else {
			copy(output, digest[0:mdlen])
		}
		strlen += mdlen
	}

	/* since we're expanding to a bit length, mask off the excess */
	if resultBitLen%8 != 0 {
		mask <<= (8 - (resultBitLen % 8))
		output[resultByteLen-1] &= mask
	}

	return output
}

// const_time_memcmp
func memcmp(a, b []byte, ablen int) int {
	if ablen == 0 {
		return 0
	}

	res := 0
	for ablen > 0 {
		ablen--
		diff := int(a[ablen]) - int(b[ablen])
		if diff != 0 {
			res = int(diff)
		}
	}
	return res
}

/*
* check whether x^3 + a*x + b is a quadratic residue
*
* save the first quadratic residue we find in the loop but do
* it in constant time.
 */
func do_equation(curve elliptic.Curve, x *big.Int) *big.Int {
	p := curve.Params().P
	a := new(big.Int)
	a.SetString("115792089210356248762697446949407573530086143415290314195533631308867097853948", 10) // TODO: What is this?
	b := curve.Params().B

	tmp1 := new(big.Int)
	tmp1.Exp(x, big.NewInt(2), p)

	y2 := new(big.Int)
	y2.Mul(tmp1, x)
	y2.Mod(y2, p)

	tmp1.Mul(a, x)
	tmp1.Mod(tmp1, p)

	y2.Add(y2, tmp1)
	y2.Mod(y2, p)

	y2.Add(y2, b)
	y2.Mod(y2, p)

	return y2
}

// not through test yet
func is_quadratic_residue(y_sqrd, prime *big.Int, qrQnr [2]*big.Int) (int, error) {
	one := big.NewInt(1)

	/*
	 * r = (random() mod p-1) + 1
	 */
	pm1 := new(big.Int)
	pm1 = pm1.Sub(prime, one)
	r, e := rand.Int(rand.Reader, pm1)
	if e != nil {
		return -1, e
	}
	r.Add(r, one)

	res := new(big.Int)
	res.SetBytes(y_sqrd.Bytes())

	/*
	 * res = val * r * r which ensures res != val but has same quadratic residocity
	 */
	res.Mul(res, r).Mod(res, prime)
	res.Mul(res, r).Mod(res, prime)

	/*
	 * if r is even (mask is -1) then multiply by qnr and our check is qnr
	 * otherwise multiply by qr and our check is qr
	 */
	is_odd := 0
	{
		mod := new(big.Int)
		if mod.Mod(r, big.NewInt(2)).Int64() != 0 {
			is_odd = 1
		}
	}
	mask := -1
	if is_odd == 1 {
		mask = 0
	}

	qr_or_qnr := new(big.Int)
	if mask == 0 {
		qr_or_qnr = qrQnr[0]
	} else {
		qr_or_qnr = qrQnr[1]
	}

	res.Mul(res, qr_or_qnr).Mod(res, prime)

	check := 1
	if mask == -1 {
		check = -1
	}

	ret := legendre(res, prime)
	if ret == -2 {
		return -1, nil
	}

	mask = 0
	if ret == check {
		mask = -1
	}

	ret = 1
	if mask == 0 {
		ret = 0
	}
	return ret, nil
}

func const_time_fill_msb(val int) (ret int) {
	uval := uint(val)
	/* Move the MSB to LSB and multiple by -1 to fill in all bits. */
	uval = uval >> (unsafe.Sizeof(uval)*8 - 1)
	ret = int(uval) * -1
	return
}

func genSeed(ctr uint8, state State) []byte {
	mac := hmac.New(sha256.New, allZero[:])
	b := (*[4]byte)(unsafe.Pointer(&state.Token))
	mac.Write(b[0:4])

	mac.Write([]byte(state.IDPeer))
	mac.Write([]byte{byte(0)})
	mac.Write([]byte(state.IDServer))
	mac.Write([]byte{byte(0)})
	mac.Write([]byte(state.Password))
	mac.Write([]byte{byte(0)})

	b[0] = ctr
	mac.Write(b[0:1])

	return mac.Sum(nil)
}

// Heavily inspired on freeradius' compute_password_element-func
func PassElement(state State) (State, error) {
	algo := elliptic.P256()
	prime := algo.Params().P
	var y_sqrd *big.Int

	/*
	* derive random quadradic residue and quadratic non-residue
	* qr+qnr (this stuff is not used until much later)
	 */
	var qr [2]*big.Int
	for pos := 0; pos < 2; pos++ {
		for i := 0; i < 100; i++ {
			randomValue, e := rand.Int(rand.Reader, prime)
			if e != nil {
				return state, e
			}

			res := legendre(randomValue, prime)
			if res == -1 {
				qr[pos] = randomValue
				break
			}
		}
	}
	if qr[0] == nil || qr[1] == nil {
		return state, fmt.Errorf("Failed generating quadradic (non)residue")
	}

	var pm1buf []byte
	{
		rnd := new(big.Int)
		rnd.Sub(prime, big.NewInt(1))
		pm1buf = rnd.Bytes()
	}

	save := 0
	mask := 0
	found := 0
	save_is_odd := 0
	var xbuf []byte

	for ctr := uint8(1); ctr < 41; ctr++ {
		pwdSeed := genSeed(ctr, state)
		rnd := new(big.Int)
		rnd.SetBytes(pwdSeed)

		// prfbuf
		prfbuf := KDF(pwdSeed, EAP_KEY, uint16(algo.Params().P.BitLen()))

		// copy prbuf into bigint
		xCandidate := new(big.Int)
		xCandidate.SetBytes(prfbuf)

		cmp := memcmp(pm1buf, prfbuf, algo.Params().P.BitLen()/8)
		skip := const_time_fill_msb(cmp)

		is_odd := 0
		{
			mod := new(big.Int)
			if mod.Mod(rnd, big.NewInt(2)).Int64() != 0 {
				is_odd = 1
			}
		}
		y_sqrd = do_equation(algo, xCandidate)

		qr_or_qnr, e := is_quadratic_residue(y_sqrd, prime, qr)
		if e != nil {
			return state, e
		}

		/*
		* if the candidate >= prime then we want to skip it
		 */
		if skip == -1 {
			qr_or_qnr = 0
		}

		/*
		* if we haven't found PWE yet (found = 0) then mask will be true,
		* if we have found PWE then mask will be false
		 */
		mask = const_time_select(found, 0, -1)

		/*
		* save will be 1 if we want to save this value-- i.e. we haven't
		* found PWE yet and this is a quadratic residue-- and 0 otherwise
		 */
		if mask == -1 {
			save = qr_or_qnr
		} else {
			save = 0
		}

		/*
		* mask will be true (-1) if we want to save this and false (0)
		* otherwise
		 */
		if save == 1 {
			mask = -1
		} else {
			mask = 0
		}

		if mask == -1 {
			xbuf = prfbuf
		}

		if mask == -1 {
			save_is_odd = is_odd
		}

		if mask == -1 {
			found = -1
		}
		found = const_time_select(mask, -1, found)
	}

	/*
	* now we can savely construct PWE
	 */
	xCandidate, y := constructPWE(algo, save_is_odd, xbuf)
	state.X = xCandidate
	state.Y = y

	if !algo.IsOnCurve(xCandidate, y) {
		return state, fmt.Errorf("Point not on elliptic curve")
	}
	return state, nil
}

func constructPWE(algo elliptic.Curve, save_is_odd int, xbuf []byte) (*big.Int, *big.Int) {
	prime := algo.Params().P

	xCandidate := new(big.Int)
	if len(xbuf) == 0 {
		panic("DevErr xbuf not set?")
	}
	xCandidate.SetBytes(xbuf)
	y_sqrd := do_equation(algo, xCandidate)

	exp := new(big.Int)
	exp.Add(prime, big.NewInt(1))
	exp.Rsh(exp, 2)

	y1 := new(big.Int)
	y1.Exp(y_sqrd, exp, prime)

	y2 := new(big.Int)
	y2.Sub(prime, y1)

	is_odd := 0
	{
		mod := new(big.Int)
		if mod.Mod(y1, big.NewInt(2)).Int64() != 0 {
			is_odd = 1
		}
	}

	mask := 0
	if save_is_odd == is_odd {
		mask = -1
	}

	var y *big.Int
	if mask == -1 {
		y = y1
	} else {
		y = y2
	}

	return xCandidate, y
}
