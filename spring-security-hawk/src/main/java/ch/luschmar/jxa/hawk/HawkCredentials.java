package ch.luschmar.jxa.hawk;

import org.springframework.util.StringUtils;

import java.util.Arrays;


public record HawkCredentials(String keyId,
                              String timestamp,
                              String nonce,
                              String method,
                              String path,
                              String host,
                              int port,
                              String hash,
                              String ext,
                              String mac) {

    public String toHawkString() {
        if (StringUtils.hasText(hash)) {
            return String.format("""
                    hawk.1.payload
                    %s
                    %s
                    %s
                    %s
                    %s
                    %d
                    %s
                    %s
                    """, timestamp, nonce, method, path, host, port, hash, ext);
        }
        return String.format("""
                hawk.1.header
                %s
                %s
                %s
                %s
                %s
                %d
                %s
                %s
                """, timestamp, nonce, method, path, host, port, hash, ext);
    }

    public byte[] toHawkBytes() {
        var str = toHawkString();
        return Arrays.copyOf(str.getBytes(), str.length());
    }
}
