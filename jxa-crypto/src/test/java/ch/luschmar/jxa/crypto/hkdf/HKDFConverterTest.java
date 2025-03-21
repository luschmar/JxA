package ch.luschmar.jxa.crypto.hkdf;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.codec.Hex;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HKDFConverterTest {
    @Test
    void test() {
        var conv = new BytesHKDFConverter<VerifyHashInput>();
        var res = conv.apply(new VerifyHashInput("441509e25c92ee103d5a1a874e6f155df25a44d06e61c894616c9e85181dba97"));

        assertEquals("a4765bf103dc057f4cf4bc2c131ddb6716e8a4333cc55e1d3c449f31f0eec4f1", new String(Hex.encode(res)));


        var keyFetchTokenConv = new FactoryHKDFConverter<>(new BytesHKDFConverter<KeyFetchTokenInput>(), new KeyFetchTokenFactory());
        var keyFetchRes = keyFetchTokenConv.apply(new KeyFetchTokenInput("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"));

        assertEquals("3d0a7c02a15a62a2882f76e39b6494b500c022a8816e048625a495718998ba60", keyFetchRes.hexTokenId());
        assertEquals("87b8937f61d38d0e29cd2d5600b3f4da0aa48ac41de36a0efe84bb4a9872ceb7", keyFetchRes.hexReqHMACKey());
        assertEquals("14f338a9e8c6324d9e102d4e6ee83b209796d5c74bb734a410e729e014a4a546", keyFetchRes.hexKeyRequestKey());


        var keyRequestKeyConv = new FactoryHKDFConverter<>(new BytesHKDFConverter<KeyRequestKeyInput>(), new RespKeyFactory());

        var respKey = keyRequestKeyConv.apply(keyFetchRes.keyRequestKeyInput());

        assertEquals("f824d2953aab9faf51a1cb65ba9e7f9e5bf91c8d8fd1ac1c8c2d31853a8a1210", respKey.hexRespHMACkey());
        assertEquals("ce7d7aa77859b2359932970bbe2101f2e80d01faf9191bd5ee52181d2f0b78098281ba8cff3925433a89f7c3095e0c89900a469d60790c833281c4df1a11c763", respKey.hexRespXORKey());

        var wrapWrapKeyConv = new FactoryHKDFConverter<>(new BytesHKDFConverter<BigStretchedPWInput>(), new WrapWrapKeyFactory());

        var wrapWrapKey = wrapWrapKeyConv.apply(new BigStretchedPWInput("441509e25c92ee103d5a1a874e6f155df25a44d06e61c894616c9e85181dba97"));

        assertEquals("3ebea117efa9faf57ce195899b2905058368e7760cc26ea58a2a1be0da7fb287", wrapWrapKey.hexWrapWrapKey());

        var wrapKb = new WrapKb(wrapWrapKey, Hex.decode("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f")); // wrapwrapKb not in docs

        assertEquals("7effe354abecbcb234a8dfc2d7644b4ad339b525589738f2d27341bb8622ecd8", wrapKb.hexWrapKb());
    }
}