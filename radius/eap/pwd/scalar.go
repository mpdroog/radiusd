package pwd

import (
	"crypto/rand"
	"math/big"
)

/*int compute_scalar_element(request_t *request, pwd_session_t *session, BN_CTX *bn_ctx)
{
	BIGNUM *mask = NULL;
	int ret = -1;

	MEM(session->private_value = BN_new());
	// EC_POINT *EC_POINT_new(const EC_GROUP *group);
	// An EC_POINT structure represents a point on a curve. A new point is constructed by calling the
	// function EC_POINT_new() and providing the group object that the point relates to.
	MEM(session->my_element = EC_POINT_new(session->group));
	MEM(session->my_scalar = BN_new());

	MEM(mask = BN_new());

	if (BN_rand_range(session->private_value, session->order) != 1) {
		printf("Unable to get randomness for private_value");
		goto error;
	}
	if (BN_rand_range(mask, session->order) != 1) {
		printf("Unable to get randomness for mask");
		goto error;
	}
	BN_add(session->my_scalar, session->private_value, mask);
	BN_mod(session->my_scalar, session->my_scalar, session->order, bn_ctx);

	// EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n,
    //  const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);
    // * n + q * m and stores the result in r. The value n may be NULL in which case the result is just
    //>>>>>> q * m (variable point multiplication). Alternatively, both q and m may be NULL, and n non-NULL,
    // in which case the result is just generator * n (fixed point multiplication)
	if (!EC_POINT_mul(session->group, session->my_element, NULL, session->pwe, mask, bn_ctx)) {
		printf("Server element allocation failed");
		goto error;
	}

	if (!EC_POINT_invert(session->group, session->my_element, bn_ctx)) {
		printf("Server element inversion failed");
		goto error;
	}

	ret = 0;

error:
	BN_clear_free(mask);

	return ret;
}*/

func Compute_scalar_element(order, pwe, algoN *big.Int) ([]byte, []byte, error) {
	scalar := new(big.Int)
	myElement := new(big.Int)

	// BN_rand_range
	privateValue, e := rand.Int(rand.Reader, order)
	if e != nil {
		return nil, nil, e
	}
	mask, e := rand.Int(rand.Reader, order)
	if e != nil {
		return nil, nil, e
	}

	scalar.Add(privateValue, mask)
	scalar.Mod(scalar, order)

	// If you do want to go on... you can "invert" a point ("negate" would be a better term...) by simply setting y = n - y
	// https://groups.google.com/g/golang-nuts/c/Epfi8BKt9Tc
	myElement.Mul(pwe, mask)
	myElement.Sub(algoN, myElement)

	return scalar.Bytes(), myElement.Bytes(), nil
}
