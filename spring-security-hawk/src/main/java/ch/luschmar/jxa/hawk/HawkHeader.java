package ch.luschmar.jxa.hawk;

import java.util.Arrays;


public record HawkHeader(String timestamp,
                         String nonce,
                         String method,
                         String path,
                         String host,
                         int port,
                         String hash,
                         String ext,
                         HawkPayload payload) {
    HawkHeader(String timestamp, String nonce, String method, String path, String host, int port, String ext) {
        this(timestamp, nonce, method, path, host, port, "", ext, null);
    }

    public String toHawkString() {
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

    public HawkHeader withPayload(HawkPayload hawkPayload) {
        return new HawkHeader(timestamp, nonce, method, path, host, port, hash, ext, hawkPayload);
    }
}
