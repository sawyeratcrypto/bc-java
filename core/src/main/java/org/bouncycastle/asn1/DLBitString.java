package org.bouncycastle.asn1;

import java.io.IOException;

/**
 * A Definite length BIT STRING
 */
public class DLBitString
    extends ASN1BitString
{
    public DLBitString(byte[] data)
    {
        this(data, 0);
    }

    public DLBitString(byte data, int padBits)
    {
        super(data, padBits);
    }

    public DLBitString(byte[] data, int padBits)
    {
        super(data, padBits);
    }

    public DLBitString(int value)
    {
        super(getBytes(value), getPadBits(value));
    }

    public DLBitString(ASN1Encodable obj) throws IOException
    {
        super(obj.toASN1Primitive().getEncoded(ASN1Encoding.DER), 0);
    }

    DLBitString(byte[] contents, boolean check)
    {
        super(contents, check);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength(boolean withTag)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contents.length);
    }

    void encode(ASN1OutputStream out, boolean withTag) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, contents);
    }

    ASN1Primitive toDLObject()
    {
        return this;
    }

    static int encodedLength(boolean withTag, int contentsLength)
    {
        return ASN1OutputStream.getLengthOfEncodingDL(withTag, contentsLength);
    }

    static void encode(ASN1OutputStream out, boolean withTag, byte[] buf, int off, int len) throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, buf, off, len);
    }

    static void encode(ASN1OutputStream out, boolean withTag, byte pad, byte[] buf, int off, int len)
        throws IOException
    {
        out.writeEncodingDL(withTag, BERTags.BIT_STRING, pad, buf, off, len);
    }

    static DLBitString fromOctetString(ASN1OctetString octetString)
    {
        return new DLBitString(octetString.getOctets(), true);
    }
}
