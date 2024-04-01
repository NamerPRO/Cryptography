package ru.namerpro.cryptography.symmetricencrypters.des;

import ru.namerpro.cryptography.api.EncryptingConversion;
import ru.namerpro.cryptography.api.KeyExpansion;
import ru.namerpro.cryptography.api.SymmetricEncrypter;
import ru.namerpro.cryptography.feistel.FeistelNetwork;
import ru.namerpro.cryptography.permutaion.Permutation;

public class DES implements SymmetricEncrypter, KeyExpansion, EncryptingConversion {

    private static final int B_BLOCK_COUNT = 8;
    private static final int BITS_IN_ONE_B_BLOCK = 6;
    private static final int FIRST_SIX_BITS_MASK = 63;
    private final int[] expansionFunction = { 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
    private final byte[][][] sTables = {
            {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            },
            {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            },
            {
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },
            {
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            {
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },
            {
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },
            {
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },
            {
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
    };
    private final int[] conclusionPermutation = { 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
    private final int[] expandedKeyInitialPermutationPartOne = { 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36};
    private final int[] expandedKeyInitialPermutationPartTwo = { 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
    private final int[] cdToRoundKeyPermutation = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
    private final int[] desInitialPermutation = { 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
    private final int[] desConclusivePermutation = { 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
    private final FeistelNetwork feistelNetwork;

    public DES(byte[] key) {
        if (key.length != 8) {
            throw new IllegalArgumentException("Wrong key size provided! Expected 64 bits (8 bytes).");
        }
        this.feistelNetwork = new FeistelNetwork(this,  key,this, 16);
    }

    @Override
    public byte[] encrypt(byte[] block) {
        byte[] permutatedBlock = Permutation.rearrange(block, getLeadingZeros(block[0]), desInitialPermutation, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        byte[] encryptedBlock = feistelNetwork.encrypt(permutatedBlock);
        return Permutation.rearrange(encryptedBlock, getLeadingZeros(encryptedBlock[0]), desConclusivePermutation, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
    }

    @Override
    public byte[] decrypt(byte[] block) {
        byte[] permutatedBlock = Permutation.rearrange(block, getLeadingZeros(block[0]), desInitialPermutation, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        byte[] decryptedBlock = feistelNetwork.decrypt(permutatedBlock);
        return Permutation.rearrange(decryptedBlock, getLeadingZeros(decryptedBlock[0]), desConclusivePermutation, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
    }

    @Override
    public byte[] runFeistelFunction(byte[] block, byte[] roundKey) {
        byte[] expandedBlock = Permutation.rearrange(block, getLeadingZeros(block[0]), expansionFunction, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        long xor = toLong48(expandedBlock) ^ toLong48(roundKey);
        byte bi;
        byte[] result = new byte[4];
        for (int i = 0; i < B_BLOCK_COUNT; ++i) {
            bi = (byte) ((xor >>> (BITS_IN_ONE_B_BLOCK * i)) & FIRST_SIX_BITS_MASK);
            int j = B_BLOCK_COUNT - i - 1;
            byte replacement = sTables[j][getRow(bi)][getColumn(bi)];
            result[j / 2] |= j % 2 == 0 ? (byte) (replacement << 4) : replacement;
        }
        return Permutation.rearrange(result, getLeadingZeros(result[0]), conclusionPermutation, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
    }

    private byte getRow(byte x) {
        return (byte) (x & 1 | (((x & 32) >>> 4) & 2));
    }

    private byte getColumn(byte x) {
        return (byte) ((x & 31) >>> 1);
    }

    private int toInt(byte[] arr) {
        return (arr[3] & 0xFF) | ((arr[2] & 0xFF) << 8L) | ((arr[1] & 0xFF) << 16L) | ((arr[0] & 0xFF) << 24L);
    }

    private long toLong48(byte[] arr) {
        return (arr[5] & 0xFF) | ((arr[4] & 0xFF) << 8L) | ((arr[3] & 0xFF) << 16L) | ((long) (arr[2] & 0xFF) << 24L) | ((long) (arr[1] & 0xFF) << 32L) | ((long) (arr[0] & 0xFF) << 40L);
    }

    private byte getLeadingZeros(byte x) {
        if (x == 0) {
            return 8;
        } else {
            return (byte) (7 - Integer.numberOfTrailingZeros(Integer.highestOneBit(x & 0xFF)));
        }
    }

    private int cycledShiftLeft(int x, int y) {
        int takenBits = (x & (((1 << y) - 1) << (28 - y))) >> (28 - y);
        return ((x << y) | takenBits) & ((1 << 28) - 1);
    }

    private long glue28(int c, int d) {
        return ((long) c << 28L) | d;
    }

    private byte[] toByteArray56(long number) {
        return new byte[] {
                (byte) (number >>> 48),
                (byte) (number >>> 40),
                (byte) (number >>> 32),
                (byte) (number >>> 24),
                (byte) (number >>> 16),
                (byte) (number >>> 8),
                (byte) number
        };
    }

    @Override
    public byte[][] expandKey(byte[] key) {
        int c = toInt(Permutation.rearrange(key, getLeadingZeros(key[0]), expandedKeyInitialPermutationPartOne, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE));
        int d = toInt(Permutation.rearrange(key, getLeadingZeros(key[0]), expandedKeyInitialPermutationPartTwo, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE));
        byte[][] roundKeys = new byte[16][];
        for (int i = 1; i <= 16; ++i) {
            int moveAmount = (i == 1 || i == 2 || i == 9 || i == 16 ? 1 : 2);
            c = cycledShiftLeft(c, moveAmount);
            d = cycledShiftLeft(d, moveAmount);
            byte[] cd = toByteArray56(glue28(c, d));
            roundKeys[i - 1] = Permutation.rearrange(cd, getLeadingZeros(cd[0]), cdToRoundKeyPermutation, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        }
        return roundKeys;
    }

}
