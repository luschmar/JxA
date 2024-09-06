package ch.luschmar.jxa.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/*
 * A standards-compliant implementation of RFC 5869
 * for HMAC-based Key Derivation Function.
 * HMAC uses HMAC SHA256 standard.
 */
public class HKDF {

	/**
	 * Used for conversion in cases in which you *know* the encoding exists.
	 */
	public static final byte[] bytes(String in) {
		try {
			return in.getBytes("UTF-8");
		} catch (java.io.UnsupportedEncodingException e) {
			return null;
		}
	}

	public static final int BLOCKSIZE     = 256 / 8;
	public static final byte[] HMAC_INPUT = bytes("Sync-AES_256_CBC-HMAC256");

	/*
	 * Step 1 of RFC 5869
	 * Get sha256HMAC Bytes
	 * Input: salt (message), IKM (input keyring material)
	 * Output: PRK (pseudorandom key)
	 */
	public static byte[] hkdfExtract(byte[] salt, byte[] IKM) {
		return digestBytes(IKM, makeHMACHasher(salt));
	}

	/*
	 * Step 2 of RFC 5869.
	 * Input: PRK from step 1, info, length.
	 * Output: OKM (output keyring material).
	 */
	public static byte[] hkdfExpand(byte[] prk, byte[] info, int len) {

		var hmacHasher = makeHMACHasher(prk);

		byte[] T  = {};
		byte[] Tn = {};

		int iterations = (int) Math.ceil(((double)len) / ((double)BLOCKSIZE));
		for (int i = 0; i < iterations; i++) {
			Tn = digestBytes(concatAll
					(Tn, info, hex2Byte(Integer.toHexString(i + 1))), hmacHasher);
			T = concatAll(T, Tn);
		}

		return Arrays.copyOfRange(T, 0, len);
	}

	/*
	 * Make HMAC key
	 * Input: key (salt)
	 * Output: Key HMAC-Key
	 */
	public static Key makeHMACKey(byte[] key) {
		if (key.length == 0) {
			key = new byte[BLOCKSIZE];
		}
		return new SecretKeySpec(key, "HmacSHA256");
	}

	/*
	 * Make an HMAC hasher
	 * Input: Key hmacKey
	 * Ouput: An HMAC Hasher
	 */
	public static Mac makeHMACHasher(byte[] key) {
		Mac hmacHasher = null;
		try {
			hmacHasher = Mac.getInstance("hmacSHA256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}

		try {
			hmacHasher.init(makeHMACKey(key));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}

		return hmacHasher;
	}

	/*
	 * Hash bytes with given hasher
	 * Input: message to hash, HMAC hasher
	 * Output: hashed byte[].
	 */
	public static byte[] digestBytes(byte[] message, Mac hasher) {
		hasher.update(message);
		byte[] ret = hasher.doFinal();
		hasher.reset();
		return ret;
	}

	/*
	 * Helper for array concatenation.
	 * Input: At least two byte[]
	 * Output: A concatenated version of them
	 */
	public static byte[] concatAll(byte[] first, byte[]... rest) {
		int totalLength = first.length;
		for (byte[] array : rest) {
			totalLength += array.length;
		}

		byte[] result = Arrays.copyOf(first, totalLength);
		int offset = first.length;

		for (byte[] array : rest) {
			System.arraycopy(array, 0, result, offset, array.length);
			offset += array.length;
		}
		return result;
	}

	/*
	 * Helper to convert Hex String to Byte Array
	 * Input: Hex string
	 * Output: byte[] version of hex string
	 */
	public static byte[] hex2Byte(String str)
	{
		if (str.length() % 2 == 1) {
			str = "0" + str;
		}

		byte[] bytes = new byte[str.length() / 2];
		for (int i = 0; i < bytes.length; i++)
		{
			bytes[i] = (byte) Integer
					.parseInt(str.substring(2 * i, 2 * i + 2), 16);
		}
		return bytes;
	}

}