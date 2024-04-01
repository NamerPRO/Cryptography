package ru.namerpro.cryptography.symmetricencrypters.deal;

import ru.namerpro.cryptography.api.KeyExpansion;
import ru.namerpro.cryptography.api.SymmetricEncrypter;
import ru.namerpro.cryptography.feistel.FeistelNetwork;
import ru.namerpro.cryptography.symmetricencrypters.des.DES;
import ru.namerpro.cryptography.utils.Utility;

public class DEAL implements SymmetricEncrypter, KeyExpansion {

    private final DES des;
    private final FeistelNetwork feistelNetwork;

    public DEAL(byte[] key) {
        if (key.length != 32 && key.length != 24 && key.length != 16) {
            throw new IllegalArgumentException("Wrong key size provided! Permitted ones are: 128 bits (16 bytes), 192 bits (24 bytes), 256 bits (32 bytes).");
        }
        this.des = new DES(new byte[] { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7 });
        this.feistelNetwork = new FeistelNetwork(new DealFeistelFunction(des), key, this, key.length == 32 ? 8 : 6);
    }

    @Override
    public byte[] encrypt(byte[] block) {
        return feistelNetwork.encrypt(block);
    }

    @Override
    public byte[] decrypt(byte[] block) {
        return feistelNetwork.decrypt(block);
    }

    @Override
    public byte[][] expandKey(byte[] keys) {
        byte[][] split = Utility.splitToBlocks(keys, 8);
        if (split.length == 2) {
            return expandKey128(split);
        }
        if (split.length == 3) {
            return expandKey192(split);
        }
        return expandKey256(split);
    }

    private byte[][] expandKey128(byte[][] keys) {
        byte[] rk1 = des.encrypt(keys[0]);
        byte[] rk2 = des.encrypt(Utility.xor(keys[1], rk1));
        byte[] rk3 = des.encrypt(Utility.xor(Utility.xor(keys[0], Utility.toByteArray(1L << 62)), rk2));
        byte[] rk4 = des.encrypt(Utility.xor(Utility.xor(keys[1], Utility.toByteArray(1L << 61)), rk3));
        byte[] rk5 = des.encrypt(Utility.xor(Utility.xor(keys[0], Utility.toByteArray(1L << 59)), rk4));
        byte[] rk6 = des.encrypt(Utility.xor(Utility.xor(keys[1], Utility.toByteArray(1L << 55)), rk5));
        return new byte[][]{rk1, rk2, rk3, rk4, rk5, rk6};
    }

    private byte[][] expandKey192(byte[][] keys) {
        byte[] rk1 = des.encrypt(keys[0]);
        byte[] rk2 = des.encrypt(Utility.xor(keys[1], rk1));
        byte[] rk3 = des.encrypt(Utility.xor(keys[2], rk2));
        byte[] rk4 = des.encrypt(Utility.xor(Utility.xor(keys[0], Utility.toByteArray(1L << 62)), rk3));
        byte[] rk5 = des.encrypt(Utility.xor(Utility.xor(keys[1], Utility.toByteArray(1L << 61)), rk4));
        byte[] rk6 = des.encrypt(Utility.xor(Utility.xor(keys[2], Utility.toByteArray(1L << 59)), rk5));
        return new byte[][]{rk1, rk2, rk3, rk4, rk5, rk6};
    }

    private byte[][] expandKey256(byte[][] keys) {
        byte[] rk1 = des.encrypt(keys[0]);
        byte[] rk2 = des.encrypt(Utility.xor(keys[1], rk1));
        byte[] rk3 = des.encrypt(Utility.xor(keys[2], rk2));
        byte[] rk4 = des.encrypt(Utility.xor(keys[3], rk3));
        byte[] rk5 = des.encrypt(Utility.xor(Utility.xor(keys[0], Utility.toByteArray(1L << 62)), rk4));
        byte[] rk6 = des.encrypt(Utility.xor(Utility.xor(keys[1], Utility.toByteArray(1L << 61)), rk5));
        byte[] rk7 = des.encrypt(Utility.xor(Utility.xor(keys[2], Utility.toByteArray(1L << 59)), rk6));
        byte[] rk8 = des.encrypt(Utility.xor(Utility.xor(keys[3], Utility.toByteArray(1L << 55)), rk7));
        return new byte[][]{rk1, rk2, rk3, rk4, rk5, rk6, rk7, rk8};
    }

}
