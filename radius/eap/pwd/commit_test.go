package pwd

import (
	"bytes"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"testing"
)

func TestGenSeed(t *testing.T) {
	expect := []byte{
		177, 229, 7, 17, 252, 1, 90, 240, 162, 70, 118, 234, 28, 77,
		197, 153, 87, 186, 131, 6, 130, 145, 69, 106, 212, 171, 76,
		184, 222, 103, 16, 124,
	}
	state := State{
		Token:    2,
		IDPeer:   "client",
		IDServer: "radius.rootdev.nl",
		Password: "minimum",
	}

	pwdSeed := genSeed(1, state)
	if !bytes.Equal(pwdSeed, expect) {
		t.Errorf("pwdSeed mismatch\nwant=%+v\nspot=%+v\n", pwdSeed, expect)
	}
}

func TestKDF(t *testing.T) {
	{
		res := KDF([]byte{0xf7, 0xe6, 0xf4, 0x40}, "EAP-pwd Hunting And Pecking", 256)
		if !bytes.Equal([]byte{
			0x0e, 0xbf, 0xcf, 0x6d, 0x1f, 0x80, 0xbc, 0x2e, 0xba, 0x68,
			0x8e, 0x07, 0x19, 0xa5, 0x2d, 0x20, 0x59, 0xaf, 0x7b, 0xfc,
			0x35, 0x82, 0x98, 0x63, 0x71, 0x5b, 0x24, 0xe0, 0x7a, 0xb2,
			0xa7, 0x0e,
		}, res) {
			t.Errorf("EAP-KDF returned invalid val")
		}

		res = KDF([]byte{}, "EAP-pwd Hunting And Pecking", 256)
		if !bytes.Equal([]byte{
			0x45, 0x2a, 0x51, 0xd7, 0x75, 0x75, 0xd3, 0x53, 0xe2, 0xe9,
			0xb2, 0xce, 0x5e, 0x0e, 0x13, 0xb6, 0x95, 0x48, 0x8a, 0x3c,
			0xee, 0xb1, 0xb7, 0x33, 0x4b, 0x4a, 0x0c, 0x58, 0x3f, 0xb6,
			0xc4, 0xaf,
		}, res) {
			t.Errorf("EAP-KDF returned invalid val")
		}
	}

	{
		res := KDF([]byte{
			0xb, 0xe1, 0xfa, 0x76, 0x27, 0x3b, 0x25, 0xb, 0xa1, 0xfe, 0xbe,
			0x32, 0x98, 0xe8, 0x73, 0xa6, 0xf5, 0x4f, 0xd, 0xaa, 0x5b, 0xb,
			0xc2, 0x3a, 0x88, 0x9d, 0xc2, 0xb5, 0xab, 0x5d, 0xf6, 0x1,
		}, "EAP-pwd Hunting And Pecking", 256)
		if !bytes.Equal([]byte{
			0xea, 0xd7, 0xd0, 0xa4, 0xb1, 0xe2, 0xa1, 0xa1, 0x0d, 0xc1,
			0x4f, 0x62, 0x90, 0x37, 0xcf, 0xa7, 0x0d, 0x3b, 0xc3, 0xdb,
			0xcc, 0x02, 0x1f, 0xe8, 0x28, 0xab, 0x5f, 0x17, 0x4f, 0x1f,
			0xde, 0x41,
		}, res) {
			t.Errorf("EAP-KDF returned invalid val")
		}
	}

	{
		res := KDF([]byte{
			0xb1, 0xe5, 0x7, 0x11, 0xfc, 0x1, 0x5a, 0xf0, 0xa2, 0x46, 0x76, 0xea, 0x1c, 0x4d, 0xc5, 0x99, 0x57, 0xba, 0x83, 0x6, 0x82, 0x91, 0x45, 0x6a, 0xd4, 0xab, 0x4c, 0xb8, 0xde, 0x67, 0x10, 0x7c,
		}, "EAP-pwd Hunting And Pecking", 256)
		if !bytes.Equal([]byte{
			0x82, 0x34, 0x07, 0x6f, 0x9c, 0xa7, 0xb1, 0x76, 0x94, 0xe4, 0x62, 0xe1, 0x96, 0x17, 0x4a, 0xe1, 0xb0, 0x0f, 0x01, 0xb5, 0x67, 0x32, 0xf3, 0xa7, 0x8a, 0x5a, 0x2c, 0xa0, 0xe6, 0x1d, 0xa1, 0x88,
		}, res) {
			t.Errorf("EAP-KDF returned invalid val")
		}

		xCandidate := new(big.Int)
		xCandidate.SetBytes(res)
		if xCandidate.String() != "58892597684469316549283746138210531455696314713865211261975374165260982133128" {
			t.Errorf("xCandidate wrong, recv=%s", xCandidate.String())
		}

		algo := elliptic.P256()
		y_sqrd := do_equation(algo, xCandidate)
		if y_sqrd.String() != "55447007940187561909173560825631678202703823087978110696691512466203005498291" {
			t.Errorf("y_sqrd wrong, recv=%s", y_sqrd.String())
		}
	}
}

func TestRandomCodeParts(t *testing.T) {
	{
		prfbuf := []byte{
			0xea, 0xd7, 0xd0, 0xa4, 0xb1, 0xe2, 0xa1, 0xa1, 0xd, 0xc1, 0x4f,
			0x62, 0x90, 0x37, 0xcf, 0xa7, 0xd, 0x3b, 0xc3, 0xdb, 0xcc, 0x2,
			0x1f, 0xe8, 0x28, 0xab, 0x5f, 0x17, 0x4f, 0x1f, 0xde, 0x41,
		}
		xCandidate := new(big.Int)
		xCandidate.SetBytes(prfbuf)

		if xCandidate.String() != "106222518690816579720990024984797970844403238576831895491707790165573497773633" {
			t.Errorf("xcandidate-logic broken")
		}
	}

	{
		prfbuf := []byte{
			0x15, 0xf2, 0xac, 0xef, 0x63, 0x8f, 0xb7, 0xbf, 0x5f, 0x94, 0xb,
			0x17, 0x91, 0x99, 0x23, 0x45, 0x9c, 0x6e, 0xe1, 0x50, 0x87, 0xc,
			0x3e, 0x99, 0xfb, 0xfc, 0x63, 0xeb, 0x6, 0xa, 0x88, 0xac,
		}
		xCandidate := new(big.Int)
		xCandidate.SetBytes(prfbuf)

		if xCandidate.String() != "9927340364208903523616813471679536296126978575170044538564284590738815748268" {
			t.Errorf("xcandidate-logic broken")
		}
	}
}

func TestConstTimeMemcmp(t *testing.T) {
	rnd := new(big.Int)
	rnd.SetString("115792089210356248762697446949407573530086143415290314195533631308867097853950", 10)
	pm1buf := rnd.Bytes()

	{
		prfbuf := []byte{
			0x82, 0x34, 0x7, 0x6f, 0x9c, 0xa7, 0xb1, 0x76, 0x94, 0xe4, 0x62, 0xe1, 0x96, 0x17, 0x4a,
			0xe1, 0xb0, 0xf, 0x1, 0xb5, 0x67, 0x32, 0xf3, 0xa7, 0x8a, 0x5a, 0x2c, 0xa0, 0xe6, 0x1d,
			0xa1, 0x88,
		}

		cmp := memcmp(pm1buf, prfbuf, SHA256_DIGEST_LENGTH)
		if cmp != 125 {
			t.Errorf("const_time_memcmp not 125, recv=%d", cmp)
		}
	}

	{
		prfbuf := []byte{
			0xff, 0xc8, 0xfe, 0x73, 0x6a, 0xf, 0x80, 0x5f, 0xfa, 0xcf, 0x6d, 0xc4, 0x51, 0x22, 0x2b,
			0x95, 0xa1, 0x2, 0xf8, 0xa0, 0x5, 0x3f, 0x16, 0x4, 0x3e, 0x1b, 0x36, 0x47, 0xe5, 0x3d,
			0xa3, 0x80,
		}
		cmp := memcmp(pm1buf, prfbuf, SHA256_DIGEST_LENGTH)
		if cmp != 55 {
			t.Errorf("const_time_memcmp not 55, recv=%d", cmp)
		}
	}
}

func TestDoEquation(t *testing.T) {
	in := "115694901956824037276141101381652098935985837042103793832734598078597697479552"
	expect := "114701460379428100965160785095280501334202495378099274588447248090220559664532"

	xCandidate := new(big.Int)
	xCandidate.SetString(in, 10)
	res := do_equation(elliptic.P256(), xCandidate)
	if res.String() != expect {
		t.Errorf("do_equation(xCandidate) is not as expected\nwant=%s\ngot =%s", expect, res.String())
	}
}

// is_quadratic_residue(y_sqrd, prime *big.Int, qrQnr [2]*big.Int) int {
func TestQuadraticResidue(t *testing.T) {
	y_sqrd := new(big.Int)
	y_sqrd.SetString("55447007940187561909173560825631678202703823087978110696691512466203005498291", 10)
	prime := new(big.Int)
	prime.SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	qrQnr := [2]*big.Int{
		new(big.Int), new(big.Int),
	}
	qrQnr[0].SetString("103769703117466815694389759640081172392142154505335303116933274851771994137197", 10)
	qrQnr[1].SetString("37775848321991679724779295706569595644464711230100607325132127056145493590774", 10)

	qr_or_qnr, e := is_quadratic_residue(y_sqrd, prime, qrQnr)
	if e != nil {
		t.Fatal(e)
	}
	if qr_or_qnr != 1 {
		t.Errorf("is_quadratic_residue should indicate residue but doesn't, ret=%d", qr_or_qnr)
	}
}

func TestQuadraticResidue2(t *testing.T) {
	y_sqrd := new(big.Int)
	y_sqrd.SetString("55447007940187561909173560825631678202703823087978110696691512466203005498291", 10)
	prime := new(big.Int)
	prime.SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	qrQnr := [2]*big.Int{
		new(big.Int), new(big.Int),
	}
	qrQnr[0].SetString("77322979120667656615107347012383054569844330766935722966535665433415191148963", 10)
	qrQnr[1].SetString("30628640191921382965373408661268375547671819091426396724442849892133080254136", 10)

	qr_or_qnr, e := is_quadratic_residue(y_sqrd, prime, qrQnr)
	if e != nil {
		t.Fatal(e)
	}
	if qr_or_qnr != 1 {
		t.Errorf("is_quadratic_residue should indicate residue but doesn't, ret=%d", qr_or_qnr)
	}
}

func TestQuadraticResidue3(t *testing.T) {
	y_sqrd := new(big.Int)
	y_sqrd.SetString("114701460379428100965160785095280501334202495378099274588447248090220559664532", 10)
	prime := new(big.Int)
	prime.SetString("115792089210356248762697446949407573530086143415290314195533631308867097853951", 10)
	qrQnr := [2]*big.Int{
		new(big.Int), new(big.Int),
	}
	qrQnr[0].SetString("77322979120667656615107347012383054569844330766935722966535665433415191148963", 10)
	qrQnr[1].SetString("30628640191921382965373408661268375547671819091426396724442849892133080254136", 10)

	qr_or_qnr, e := is_quadratic_residue(y_sqrd, prime, qrQnr)
	if e != nil {
		t.Fatal(e)
	}
	if qr_or_qnr != 0 {
		t.Errorf("is_quadratic_residue should indicate residue but doesn't, ret=%d", qr_or_qnr)
	}
}

func TestMSB(t *testing.T) {
	kv := map[int]int{
		-1:  -1,
		0:   0,
		1:   0,
		7:   0,
		3:   0,
		15:  0,
		125: 0,
		63:  0,
		31:  0,
		127: 0,
	}
	for in, out := range kv {
		res := const_time_fill_msb(in)
		if res != out {
			t.Errorf("const_time_fill_msb(%d)=%d instead of %d", in, res, out)
		}
	}
}

// Collected X,Y's that are valid with elliptic SHA256
func TestValidXYs(t *testing.T) {
	x := new(big.Int)
	x.SetString("58892597684469316549283746138210531455696314713865211261975374165260982133128", 10)
	y := new(big.Int)
	y.SetString("94606997391825362391489568664709657285756749222426424030291053190742610957824", 10)

	algo := elliptic.P256()
	if !algo.IsOnCurve(x, y) {
		t.Errorf("Point does not exist on elliptic curve")
	}
}

func TestY12(t *testing.T) {
	algo := elliptic.P256()

	xCandidate := new(big.Int)
	xCandidate.SetString("58892597684469316549283746138210531455696314713865211261975374165260982133128", 10)

	y1 := new(big.Int)
	y1.SetString("94606997391825362391489568664709657285756749222426424030291053190742610957824", 10)

	y2 := new(big.Int)
	y2.SetString("21185091818530886371207878284697916244329394192863890165242578118124486896127", 10)

	if !algo.IsOnCurve(xCandidate, y1) {
		t.Errorf("Point does not exist on elliptic curve")
	}
	if !algo.IsOnCurve(xCandidate, y2) {
		t.Errorf("Point does not exist on elliptic curve")
	}
}

func TestY12Invalid(t *testing.T) {
	algo := elliptic.P256()

	xCandidate := new(big.Int)
	xCandidate.SetString("115382133222002275846668153164802922537137138807847310707853843643949800504304", 10)

	y1 := new(big.Int)
	y1.SetString("19648124362109874798177227742201732913683995740104372753323905972182974572931", 10)

	y2 := new(big.Int)
	y2.SetString("96143964848246373964520219207205840616402147675185941442209725336684123281020", 10)

	if algo.IsOnCurve(xCandidate, y1) {
		t.Errorf("Point should not exist on elliptic curve")
	}
	if algo.IsOnCurve(xCandidate, y2) {
		t.Errorf("Point should not exist on elliptic curve")
	}
}

// Test second part of PassElement
func TestConstructPWE(t *testing.T) {
	algo := elliptic.P256()
	xBig := new(big.Int)
	xBig.SetString("58892597684469316549283746138210531455696314713865211261975374165260982133128", 10)

	for i := 0; i < 2; i++ {
		xCandidate, y := constructPWE(algo, i, xBig.Bytes())
		if !algo.IsOnCurve(xCandidate, y) {
			t.Errorf("Point does not exist on elliptic curve")
		}
	}
}

// Test everything combined
func TestPassElement(t *testing.T) {
	state, e := PassElement(State{
		Token:    2,
		IDPeer:   "client",
		IDServer: "radius.rootdev.nl",
		Password: "minimum",
	})
	if e != nil {
		t.Error(e)
	}
	if testing.Verbose() {
		fmt.Printf("state.X=%s\nstate.Y=%s\n", state.X.String(), state.Y.String())
	}

	if state.X.String() != "58892597684469316549283746138210531455696314713865211261975374165260982133128" {
		t.Errorf("Invalid X calculated")
	}
	if state.Y.String() != "94606997391825362391489568664709657285756749222426424030291053190742610957824" {
		t.Errorf("Invalid Y calculated")
	}
}
