package ch.luschmar.jxa.crypto;

import org.springframework.security.crypto.codec.Hex;

public record KeyFetchTokenResult(byte[] tokenId, byte[] reqHMACKey, byte[] keyRequestKey) implements HKDFResult {
    String hexTokenId() {
        return new String(Hex.encode(tokenId));
    }

    String  hexReqHMACKey(){
        return new String(Hex.encode(reqHMACKey));
    }

    String hexKeyRequestKey(){
        return new String(Hex.encode(keyRequestKey));
    }
}
