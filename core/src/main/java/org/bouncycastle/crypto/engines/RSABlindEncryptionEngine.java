package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 *  A placeholder that doesn't do anything but only return the input, used in PKCS1Encoding to unpadding without decryption
 */
public class RSABlindEncryptionEngine
        implements AsymmetricBlockCipher
{
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private RSACoreEngine    core = new RSACoreEngine();
    private RSAKeyParameters key;
    private SecureRandom     random;
    private RSABlindingEngine blindingEngine;

    /**
     * initialise the RSA engine.
     *
     * @param forEncryption true if we are encrypting, false otherwise.
     * @param param the necessary RSA key parameters.
     */
    public void init(
            boolean             forEncryption,
            CipherParameters    param)
    {
        core.init(forEncryption, param);
    }

    /**
     * Return the maximum size for an input block to this engine.
     * For RSA this is always one byte less than the key size on
     * encryption, and the same length as the key size on decryption.
     *
     * @return maximum size for an input block.
     */
    public int getInputBlockSize()
    {
        return core.getInputBlockSize();
    }

    /**
     * Return the maximum size for an output block to this engine.
     * For RSA this is always one byte less than the key size on
     * decryption, and the same length as the key size on encryption.
     *
     * @return maximum size for an output block.
     */
    public int getOutputBlockSize()
    {
        return core.getOutputBlockSize();
    }

    /**
     * Process a single block using the basic RSA algorithm.
     *
     * @param in the input array.
     * @param inOff the offset into the input buffer where the data starts.
     * @param inLen the length of the data to be processed.
     * @return the input.
     */
    public byte[] processBlock(
            byte[]  in,
            int     inOff,
            int     inLen)
    {
        return in;
    }
}
