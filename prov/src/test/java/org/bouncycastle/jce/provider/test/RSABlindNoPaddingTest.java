package org.bouncycastle.jce.provider.test;

import org.bouncycastle.crypto.engines.RSABlindingEngine;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
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

public class RSABlindNoPaddingTest extends SimpleTest {


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

        KeyFactory fact = KeyFactory.getInstance("RSA", "BC");

        PrivateKey privKey = fact.generatePrivate(privKeySpec);
        PublicKey pubKey = fact.generatePublic(pubKeySpec);
        RSAKeyParameters keyParameters = new RSAKeyParameters(false, pubKeySpec.getModulus(), pubKeySpec.getPublicExponent());

        // encryption
        Cipher enCipher = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
        enCipher.init(Cipher.ENCRYPT_MODE, pubKey);
        byte[] ciphertext = enCipher.doFinal(plaintext);
        BigInteger cipherInteger = new BigInteger(ciphertext);
        System.out.println("cipher: " + Arrays.toString(cipherInteger.toByteArray()));

        // blind
        BigInteger r = new BigInteger("9187672208884584551578626597721077350571447838464860772294562561142651027527325047236339031520048141566779774610930475");
        RSABlindingEngine blindingEngine = new RSABlindingEngine();
        blindingEngine.init(true, new RSABlindingParameters(keyParameters, r));
        byte[] blindedInput =  blindingEngine.processBlock(ciphertext, 0, ciphertext.length);
        System.out.println("blind: " + Arrays.toString(blindedInput));

        // raw decrypt
        Cipher deCipher = Cipher.getInstance("RSA/ECB/NoPadding", "BC");
        deCipher.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decrypted = deCipher.doFinal(blindedInput);
        System.out.println("decrypted: " + Arrays.toString(decrypted));

        // un blind
        RSABlindingEngine unBlindingEngine = new RSABlindingEngine();
        unBlindingEngine.init(false, new RSABlindingParameters(keyParameters, r));
        byte[] un_blind = unBlindingEngine.processBlock(decrypted, 0, decrypted.length);
        System.out.println("unblind: " + Arrays.toString(un_blind));
        System.out.println("message: " + Arrays.toString(plaintext));

        if (!areEqual(un_blind, plaintext))
        {
            fail("Blinding process failed");
        }



    }

    public static void main(
            String[]    args)
    {
        Security.addProvider(new BouncyCastleProvider());

        runTest(new RSABlindNoPaddingTest());
    }
}
