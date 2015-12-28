// MSCHAPv2 implementation
// How does v2 differ from v1?

// Removed LMAuthenticator and using this space for peerChallenge
// 3-way auth by adding S=XXX

package mschap

import (
   "crypto/sha1"
   "fmt"
   "golang.org/x/crypto/md4"
   "strings"
)

type Res struct {
   ChallengeResponse []byte
   AuthenticatorResponse string
}

// SHA1 of all challenges + username
func challengeHash(peerChallenge []byte, authChallenge []byte, userName []byte) []byte {
   enc := sha1.New()
   enc.Write(peerChallenge)
   enc.Write(authChallenge)
   enc.Write(userName)
   return enc.Sum(nil)[:8]
}

// GenerateNTResponse, GenerateAuthenticatorResponse
func Encryptv2(authenticatorChallenge []byte, peerChallenge []byte, username string, pass string) (*Res, error) {
   var (
      out Res
      e error
   )

	challenge := challengeHash(peerChallenge, authenticatorChallenge, []byte(username))
   passHash := ntPasswordHash(ntPassword(pass))

   out.ChallengeResponse, e = ntChallengeResponse(challenge, passHash)
   if e != nil {
      return nil, e
   }
   out.AuthenticatorResponse = authResponse(pass, out.ChallengeResponse, peerChallenge, authenticatorChallenge, username)

   return &out, nil
}

// HashNtPasswordHash
// Hash the MD4 to a hashhash MD4
func hashNtPasswordHash(hash []byte) []byte {
   d := md4.New()
   d.Write(hash)
   return d.Sum(nil)
}

// GenerateAuthenticatorResponse
func authResponse(pass string, ntResponse []byte, peerChallenge []byte, authChallenge []byte, userName string) string {
   var x []byte
   {
      magic := []byte{
         0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
         0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
         0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
         0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
      }
      hashHash := hashNtPasswordHash(ntPasswordHash(ntPassword(pass)))

      enc := sha1.New()
      enc.Write(hashHash)
      enc.Write(ntResponse)
      enc.Write(magic)
      x = enc.Sum(nil)
   }

   var y []byte
   {
      magic := []byte{
         0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
         0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
         0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
         0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
         0x6E,
      }
      challenge := challengeHash(peerChallenge, authChallenge, []byte(userName))

      enc := sha1.New()
      enc.Write(x)
      enc.Write(challenge)
      enc.Write(magic)
      y = enc.Sum(nil)
   }

   return "S=" + strings.ToUpper(fmt.Sprintf("%x", y))
}