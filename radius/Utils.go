package radius

import (
    "crypto/md5"
    "bytes"
)

func DecryptPassword(raw []byte, reqAuth []byte, secret string) string {
    if len(raw) != 16 {
        panic("User-Password invalid length (not 16 octets)")
    }

	h := md5.New()
    h.Write([]byte(secret))
    h.Write(reqAuth)
    digest := h.Sum(nil)

    for i := 0; i < len(raw); i++ {
    	// XOR
        raw[i] = raw[i] ^ digest[i]
    }

    raw = bytes.TrimRight(raw, string([]rune{0}))
    return string(raw)
}

// Return non-empty string on error
func ValidateAcctRequest(p *Packet) string {
	// the following attributes MUST NOT be present in an Accounting-
    // Request:  User-Password, CHAP-Password, Reply-Message, State.
    if _, there := p.Attrs[UserPassword]; there {
    	return "UserPassword not allowed"
    }
    if _, there := p.Attrs[CHAPPassword]; there {
    	return "CHAPPassword not allowed"
    }
    if _, there := p.Attrs[ReplyMessage]; there {
    	return "ReplyMessage not allowed"
    }
    if _, there := p.Attrs[State]; there {
    	return "State not allowed"
    }

    // Either NAS-IP-Address or NAS-Identifier MUST be present in a
    // RADIUS Accounting-Request.
    if _, there := p.Attrs[NASIPAddress]; !there {
    	return "NASIPAddress missing"
    }
    if _, there := p.Attrs[NASIdentifier]; !there {
    	return "NASIdentifier missing"
    }

	// It SHOULD contain a NAS-Port or NAS-
    // Port-Type attribute or both unless the service does not involve a
    // port or the NAS does not distinguish among its ports.
    if _, there := p.Attrs[NASPort]; !there {
    	return "NASPort missing"
    }
    if _, there := p.Attrs[NASPortType]; !there {
    	return "NASPortType missing"
    }

    // All OK!
    return "";
}