package ch.luschmar.jxa.crypto;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Hex;

import static org.junit.jupiter.api.Assertions.*;

class HKDFConverterTest {
    @Test
    void test() {
        var conv = new BytesHKDFConverter<VerifyHashInput>();
        var res = conv.apply(new VerifyHashInput("441509e25c92ee103d5a1a874e6f155df25a44d06e61c894616c9e85181dba97"));

        assertEquals("a4765bf103dc057f4cf4bc2c131ddb6716e8a4333cc55e1d3c449f31f0eec4f1", new String(Hex.encode(res)));


        var keyFetchTokenConv = new FactoryHKDFConverter<>(new BytesHKDFConverter<KeyFetchTokenInput>(), new KeyFetchTokenResultFactory());
        var keyFetchRes =  keyFetchTokenConv.apply(new KeyFetchTokenInput("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));

        assertEquals("3d0a7c02a15a62a2882f76e39b6494b500c022a8816e048625a495718998ba60", keyFetchRes.hexTokenId());
        assertEquals("87b8937f61d38d0e29cd2d5600b3f4da0aa48ac41de36a0efe84bb4a9872ceb7", keyFetchRes.hexReqHMACKey());
        assertEquals("14f338a9e8c6324d9e102d4e6ee83b209796d5c74bb734a410e729e014a4a546", keyFetchRes.hexKeyRequestKey());
    }
}