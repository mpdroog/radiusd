// https://github.com/FreeRADIUS/freeradius-server/blob/9e5e8f2f912ad2da8ac6e176ac3a606333469937/src/modules/rlm_eap/types/rlm_eap_pwd/eap_pwd.c#L682
package pwd

import (
	"crypto/elliptic"
	"fmt"
	"math/big"
)

const SHA256_DIGEST_LENGTH = 32

var (
	allZero [SHA256_DIGEST_LENGTH]byte
)

// process_peer_commit
func ProcessPeerCommit(elementScalar []byte) error {
	algo := elliptic.P256()

	// TODO: This could just be static number?
	primeByteLen := algo.Params().P.BitLen() / 8
	orderByteLen := algo.Params().N.BitLen() / 8

	if len(elementScalar) < (2*primeByteLen)+orderByteLen {
		return fmt.Errorf(
			"elementScalar invalid length recv=%d want=%d",
			len(elementScalar),
			(2*primeByteLen)+orderByteLen,
		)
	}

	bigX := new(big.Int)
	bigY := new(big.Int)
	bigScalar := new(big.Int)

	bigX.SetBytes(elementScalar[0:primeByteLen])
	bigY.SetBytes(elementScalar[primeByteLen : primeByteLen+primeByteLen])
	bigScalar.SetBytes(elementScalar[primeByteLen*2 : (primeByteLen*2)+orderByteLen])

	if bigScalar.Uint64() == uint64(1) || bigScalar.Uint64() == uint64(0) {
		return fmt.Errorf("Scalar cannot be 1 or 0")
	}
	if bigScalar.Cmp(algo.Params().N) >= 0 {
		return fmt.Errorf("Scalar same or bigger? scalar=%s N=%s", bigScalar.String(), algo.Params().N.String())
	}

	if !algo.IsOnCurve(bigX, bigY) {
		return fmt.Errorf("Point does not exist on elliptic curve")
	}

	// TODO: check to ensure peer's element is not in a small sub-group
	// TODO: detect reflection attacks - if myElement == peerElement && myScalar == peerScalar
	// K= session->pwe * session->peer_scalar
	// K= K + session->peer_element
	// K= K * session->private_value
	//
	// r, s, e := ecdsa.Sign(elliptic.P256(), priv.Privkey, sum)
	/* compute the shared key, k
	   if ((!EC_POINT_mul(session->group, K, NULL, session->pwe, session->peer_scalar, bn_ctx)) ||
	       (!EC_POINT_add(session->group, K, K, session->peer_element, bn_ctx)) ||
	       (!EC_POINT_mul(session->group, K, NULL, K, session->private_value, bn_ctx))) {
	           printf("Unable to compute shared key, k");
	           goto finish;
	   }*/

	return nil
}

// valid!
func const_time_select(mask, true_val, false_val int) int {
	return (mask & true_val) | ((^mask) & false_val)
}

// valid!
func legendre(randomValue *big.Int, primeN *big.Int) int {
	pm1over2 := new(big.Int)
	pm1over2.Sub(primeN, big.NewInt(1))
	pm1over2.Rsh(pm1over2, 1)

	res := new(big.Int)
	res.Exp(randomValue, pm1over2, primeN)

	symbol := -1
	mask := 0
	if res.Uint64() == uint64(1) {
		mask = -1
	}
	symbol = const_time_select(mask, 1, symbol)

	mask = 0
	if res.Uint64() == uint64(0) {
		mask = -1
	}

	symbol = const_time_select(mask, -1, symbol)

	return symbol
}
