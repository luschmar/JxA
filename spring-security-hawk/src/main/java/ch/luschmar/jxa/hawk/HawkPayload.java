package ch.luschmar.jxa.hawk;

import java.util.Arrays;


public record HawkPayload(String contentType, String payload) {

    public String toHawkString() {
        return String.format("""
                hawk.1.payload
                %s
                %s
                """, contentType, payload);
    }

    public byte[] toHawkBytes() {
        var str = toHawkString();
        return Arrays.copyOf(str.getBytes(), str.length());
    }
}
