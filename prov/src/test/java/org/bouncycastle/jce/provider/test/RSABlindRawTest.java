package org.bouncycastle.jce.provider.test;

import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.test.SimpleTest;

import javax.crypto.Cipher;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

public class RSABlindRawTest extends SimpleTest {


    private RSAPublicKeySpec pubKeySpec = new RSAPublicKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16));

    private RSAPrivateCrtKeySpec privKeySpec = new RSAPrivateCrtKeySpec(
            new BigInteger("b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7", 16),
            new BigInteger("11", 16),
            new BigInteger("9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89", 16),
            new BigInteger("c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb", 16),
            new BigInteger("f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5", 16),
            new BigInteger("b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391", 16),
            new BigInteger("d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd", 16),
            new BigInteger("b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19", 16));

    @Override
    public String getName() {
        return "RSABlindTest";
    }

    @Override
    public void performTest() throws Exception {


        String message = "SADJEIGPDKMCJQHTEJDNDQOPCMBMN";
        byte[] plaintext = message.getBytes(StandardCharsets.UTF_8);
        BigInteger plainInteger = new BigInteger(plaintext);


        BigInteger m = pubKeySpec.getModulus();

        // raw encryption
        BigInteger cipherInteger = plainInteger.modPow(pubKeySpec.getPublicExponent(), pubKeySpec.getModulus());
        System.out.println("cipher: " + Arrays.toString(cipherInteger.toByteArray()));

        // blind
        BigInteger r = new BigInteger("9187672208884584551578626597721077350571447838464860772294562561142651027527325047236339031520048141566779774610930475");
        BigInteger blindedInput = r.modPow(pubKeySpec.getPublicExponent(), m).multiply(cipherInteger).mod(m);
        System.out.println("blind: " + Arrays.toString(blindedInput.toByteArray()));

        // raw decrypt
        BigInteger p = privKeySpec.getPrimeP();
        BigInteger q = privKeySpec.getPrimeQ();
        BigInteger dP = privKeySpec.getPrimeExponentP();
        BigInteger dQ = privKeySpec.getPrimeExponentQ();
        BigInteger qInv = privKeySpec.getCrtCoefficient();

        BigInteger mP, mQ, h, decrypted;

        // mP = ((input mod p) ^ dP)) mod p
        mP = (blindedInput.remainder(p)).modPow(dP, p);

        // mQ = ((input mod q) ^ dQ)) mod q
        mQ = (blindedInput.remainder(q)).modPow(dQ, q);

        // h = qInv * (mP - mQ) mod p
        h = mP.subtract(mQ);
        h = h.multiply(qInv);
        h = h.mod(p);               // mod (in Java) returns the positive residual

        // m = h * q + mQ
        decrypted = h.multiply(q);
        decrypted = decrypted.add(mQ);
        System.out.println("decrypted: " + Arrays.toString(decrypted.toByteArray()));


        // un blind
        BigInteger rInv = BigIntegers.modOddInverse(m, r);
        BigInteger result = decrypted.multiply(rInv).mod(m);
        System.out.println("unblind: " + Arrays.toString(result.toByteArray()));
        System.out.println("message: " + Arrays.toString(plainInteger.toByteArray()));

        byte[] unBlind = result.toByteArray();
        if (!areEqual(unBlind, plaintext))
        {
            fail("Blinding process failed");
        }



    }

    public static void main(
            String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new RSABlindRawTest());
    }
}
