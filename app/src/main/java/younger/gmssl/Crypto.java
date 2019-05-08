package younger.gmssl;

public class Crypto {
    public Crypto(){
        System.loadLibrary("younger");
    }

    public native byte[] aesEnc(byte in[], int length, byte key[]);

    public native byte[] aesDec(byte in[], int length, byte key[]);

    public native byte[] sm4Enc(byte in[], int length, byte key[]);

    public native byte[] sm4Dec(byte in[], int length, byte key[]);

    public native byte[] sm2Enc(byte in[], int length, byte keyA[], byte keyB[]);

    public native byte[] sm2Dec(byte in[], int length, byte key[]);
}
