package mschap

import (
   "crypto/sha1"
)

// SHA1 of all challenges + username
/*
   IN 16-octet               PeerChallenge,
   IN 16-octet               AuthenticatorChallenge,
   IN  0-to-256-char         UserName,
   OUT 8-octet               Challenge
*/
func challengeHash(peerChallenge []byte, authChallenge []byte, userName []byte) []byte {
   enc := sha1.New()
   enc.Write(peerChallenge)
   enc.Write(authChallenge)
   enc.Write(userName)
   return enc.Sum(nil)[:8]
}

/*
GenerateNTResponse(
   IN  16-octet              AuthenticatorChallenge,
   IN  16-octet              PeerChallenge,
   IN  0-to-256-char         UserName,
   IN  0-to-256-unicode-char Password,
   OUT 24-octet              Response )
   {
      8-octet  Challenge
      16-octet PasswordHash

      ChallengeHash( PeerChallenge, AuthenticatorChallenge, UserName,
                     giving Challenge)

      NtPasswordHash( Password, giving PasswordHash )
      ChallengeResponse( Challenge, PasswordHash, giving Response )
   }
*/
func Encryptv2(authenticatorChallenge []byte, peerChallenge []byte, username string, pass string) ([]byte, error) {
	challenge := challengeHash(peerChallenge, authenticatorChallenge, []byte(username))
   passHash := ntPasswordHash(ntPassword(pass))
   return ntChallengeResponse(challenge, passHash)
}
