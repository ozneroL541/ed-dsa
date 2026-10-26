// Implementazione didattica di Ed25519 che segue gli Algorithm 1 e 2 del paper
// "Taming the many EdDSAs" (IACR ePrint 2020/1244).
//
// ATTENZIONE: usa math/big, quindi NON è a tempo costante. Va bene per
// studiare l'algoritmo e testare interoperabilità, non per produzione
// (lì usare crypto/ed25519 o filippo.io/edwards25519).
package main

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
)

const (
	SecretKeySize = 32
	PublicKeySize = 32
	SignatureSize = 64
)

// ---------------------------------------------------------------------------
// Parametri della curva: -x² + y² = 1 + d·x²·y²  su GF(2^255 - 19)
// ---------------------------------------------------------------------------

var (
	p, L, d, d2, sqrtM1 *big.Int
	pMinus2, pPlus3Div8 *big.Int

	identity  point // punto neutro (0, 1)
	basePoint point // B
)

func mustBig(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("bad constant")
	}
	return n
}

func init() {
	one := big.NewInt(1)

	// p = 2^255 - 19
	p = new(big.Int).Sub(new(big.Int).Lsh(one, 255), big.NewInt(19))
	pMinus2 = new(big.Int).Sub(p, big.NewInt(2))
	pPlus3Div8 = new(big.Int).Rsh(new(big.Int).Add(p, big.NewInt(3)), 3)

	// L = 2^252 + 27742317777372353535851937790883648493 (ordine del sottogruppo primo)
	L = new(big.Int).Add(new(big.Int).Lsh(one, 252), mustBig("27742317777372353535851937790883648493"))

	// d = -121665/121666 mod p
	d = fmul(new(big.Int).Neg(big.NewInt(121665)), finv(big.NewInt(121666)))
	d2 = fadd(d, d)

	// sqrt(-1) = 2^((p-1)/4) mod p
	sqrtM1 = new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(p, one), 2), p)

	identity = point{big.NewInt(0), big.NewInt(1), big.NewInt(1), big.NewInt(0)}

	// B: y = 4/5, x "positivo" (bit meno significativo 0)
	by := fmul(big.NewInt(4), finv(big.NewInt(5)))
	enc := leBytes(by, 32) // bit di segno = 0
	var err error
	basePoint, err = decodePoint(enc)
	if err != nil {
		panic(err)
	}
}

// ---------------------------------------------------------------------------
// Aritmetica nel campo GF(p)
// ---------------------------------------------------------------------------

func fadd(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), p) }
func fsub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), p) }
func fmul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), p) }
func finv(a *big.Int) *big.Int    { return new(big.Int).Exp(a, pMinus2, p) }

// ---------------------------------------------------------------------------
// Punti in coordinate estese (X:Y:Z:T), x = X/Z, y = Y/Z, T = XY/Z
// ---------------------------------------------------------------------------

type point struct{ X, Y, Z, T *big.Int }

// pointAdd: formula unificata e completa per a = -1 (RFC 8032 §5.1.4).
// Funziona anche per il raddoppio e con il punto neutro.
func pointAdd(P, Q point) point {
	A := fmul(fsub(P.Y, P.X), fsub(Q.Y, Q.X))
	B := fmul(fadd(P.Y, P.X), fadd(Q.Y, Q.X))
	C := fmul(fmul(P.T, d2), Q.T)
	D := fmul(fadd(P.Z, P.Z), Q.Z)
	E := fsub(B, A)
	F := fsub(D, C)
	G := fadd(D, C)
	H := fadd(B, A)
	return point{fmul(E, F), fmul(G, H), fmul(F, G), fmul(E, H)}
}

func pointNeg(P point) point {
	zero := big.NewInt(0)
	return point{fsub(zero, P.X), new(big.Int).Set(P.Y), new(big.Int).Set(P.Z), fsub(zero, P.T)}
}

// scalarMult calcola k·P con double-and-add (NON costante nel tempo).
func scalarMult(k *big.Int, P point) point {
	Q := identity
	for i := k.BitLen() - 1; i >= 0; i-- {
		Q = pointAdd(Q, Q)
		if k.Bit(i) == 1 {
			Q = pointAdd(Q, P)
		}
	}
	return Q
}

func mulBy8(P point) point {
	P = pointAdd(P, P)
	P = pointAdd(P, P)
	return pointAdd(P, P)
}

func isIdentity(P point) bool {
	// (X:Y:Z:T) è il neutro  <=>  X = 0 e Y = Z
	return P.X.Sign() == 0 && P.Y.Cmp(P.Z) == 0
}

// ---------------------------------------------------------------------------
// Codifica / decodifica (little endian; bit 255 = parità di x)
// ---------------------------------------------------------------------------

func reverse(b []byte) []byte {
	out := make([]byte, len(b))
	for i := range b {
		out[len(b)-1-i] = b[i]
	}
	return out
}

func leBytes(n *big.Int, size int) []byte {
	buf := make([]byte, size)
	n.FillBytes(buf)
	return reverse(buf)
}

func leInt(b []byte) *big.Int { return new(big.Int).SetBytes(reverse(b)) }

func encodePoint(P point) []byte {
	zinv := finv(P.Z)
	x := fmul(P.X, zinv)
	y := fmul(P.Y, zinv)
	out := leBytes(y, 32)
	out[31] |= byte(x.Bit(0)) << 7
	return out
}

// decodePoint rifiuta anche le codifiche NON canoniche (riga 3 di Algorithm 2).
func decodePoint(b []byte) (point, error) {
	if len(b) != 32 {
		return point{}, errors.New("lunghezza non valida")
	}
	sign := uint(b[31] >> 7)
	yb := append([]byte(nil), b...)
	yb[31] &= 0x7f
	y := leInt(yb)
	if y.Cmp(p) >= 0 { // y >= p: non canonico
		return point{}, errors.New("y non canonica (y >= p)")
	}

	// x² = (y²-1) / (d·y²+1)
	y2 := fmul(y, y)
	u := fsub(y2, big.NewInt(1))
	v := fadd(fmul(d, y2), big.NewInt(1))
	x2 := fmul(u, finv(v))

	// radice quadrata modulo p (p ≡ 5 mod 8)
	x := new(big.Int).Exp(x2, pPlus3Div8, p)
	if fmul(x, x).Cmp(x2) != 0 {
		x = fmul(x, sqrtM1)
		if fmul(x, x).Cmp(x2) != 0 {
			return point{}, errors.New("il punto non è sulla curva")
		}
	}
	if x.Sign() == 0 && sign == 1 { // "-0": non canonico
		return point{}, errors.New("x = 0 con bit di segno 1 (non canonico)")
	}
	if x.Bit(0) != sign {
		x = new(big.Int).Sub(p, x)
	}
	return point{x, y, big.NewInt(1), fmul(x, y)}, nil
}

// ---------------------------------------------------------------------------
// Algorithm 1 — Key Generation
// ---------------------------------------------------------------------------

// expandSecret implementa le righe 2-3: (h0..h511) <- SHA512(sk); s = clamp(h[0:32]).
// Restituisce lo scalare segreto s e il prefisso h[32:64] usato per il nonce.
func expandSecret(sk []byte) (s *big.Int, prefix []byte) {
	h := sha512.Sum512(sk)
	lo := append([]byte(nil), h[:32]...)
	lo[0] &= 248  // azzera i 3 bit bassi  (h0, h1, h2)
	lo[31] &= 127 // azzera il bit 255
	lo[31] |= 64  // imposta il bit 254   (2^254)
	return leInt(lo), h[32:]
}

// GenerateKey: riga 1 (sk casuale uniforme in {0,1}^256) + PublicKey.
func GenerateKey() (sk, pk []byte, err error) {
	sk = make([]byte, SecretKeySize)
	if _, err = rand.Read(sk); err != nil {
		return nil, nil, err
	}
	return sk, PublicKey(sk), nil
}

// PublicKey: riga 4, A = s·B.
func PublicKey(sk []byte) []byte {
	s, _ := expandSecret(sk)
	return encodePoint(scalarMult(s, basePoint))
}

// ---------------------------------------------------------------------------
// Algorithm 1 — Signature Generation
// ---------------------------------------------------------------------------

func Sign(sk, msg []byte) []byte {
	s, prefix := expandSecret(sk)
	A := encodePoint(scalarMult(s, basePoint))

	// 5: r := SHA512(h256 || ... || h511 || M)
	hr := sha512.New()
	hr.Write(prefix)
	hr.Write(msg)
	r := new(big.Int).Mod(leInt(hr.Sum(nil)), L)

	// 6: R := r·B   (9: codifica canonica del punto)
	R := encodePoint(scalarMult(r, basePoint))

	// 7: S := (r + SHA512(R||A||M) * s) mod L
	hk := sha512.New()
	hk.Write(R)
	hk.Write(A)
	hk.Write(msg)
	k := leInt(hk.Sum(nil))
	S := new(big.Int).Mul(k, s)
	S.Add(S, r).Mod(S, L)

	// 8: S codificato canonicamente (già ridotto mod L)
	return append(R, leBytes(S, 32)...)
}

// ---------------------------------------------------------------------------
// Algorithm 2 — Signature Verification (singola firma, con tutti i controlli)
// ---------------------------------------------------------------------------

func Verify(pk, msg, sig []byte) bool {
	if len(pk) != PublicKeySize || len(sig) != SignatureSize {
		return false
	}
	Rb, Sb := sig[:32], sig[32:]

	// 1: rifiuta se S ∉ {0, ..., L-1}
	S := leInt(Sb)
	if S.Cmp(L) >= 0 {
		return false
	}

	// 3: rifiuta se A o R sono non canonici (decodePoint lo controlla;
	//    fallisce anche se il punto non sta sulla curva)
	A, err := decodePoint(pk)
	if err != nil {
		return false
	}
	R, err := decodePoint(Rb)
	if err != nil {
		return false
	}

	// 2: rifiuta se A è uno degli 8 punti di ordine piccolo
	//    (A ha ordine che divide 8  <=>  8·A = neutro)
	if isIdentity(mulBy8(A)) {
		return false
	}

	// 4: h = SHA512(R||A||M) mod L
	hh := sha512.New()
	hh.Write(Rb)
	hh.Write(pk)
	hh.Write(msg)
	h := new(big.Int).Mod(leInt(hh.Sum(nil)), L)

	// 5: accetta se 8(S·B) - 8R - 8(h·A) = 0   (equazione col cofattore)
	T := pointAdd(scalarMult(S, basePoint), pointNeg(R))
	T = pointAdd(T, pointNeg(scalarMult(h, A)))
	return isIdentity(mulBy8(T))
}

// ---------------------------------------------------------------------------

func main() {
	sk, pk, err := GenerateKey()
	if err != nil {
		panic(err)
	}
	msg := []byte("ciao, Ed25519!")
	sig := Sign(sk, msg)

	fmt.Printf("sk  = %x\n", sk)
	fmt.Printf("pk  = %x\n", pk)
	fmt.Printf("sig = %x\n", sig)
	fmt.Println("verifica (messaggio corretto):  ", Verify(pk, msg, sig))
	fmt.Println("verifica (messaggio alterato):  ", Verify(pk, []byte("ciao, Ed25519?"), sig))
}