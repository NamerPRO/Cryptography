package ru.namerpro.cryptography.symmetricencrypters.rijndael;

import org.apache.commons.lang3.tuple.Triple;
import ru.namerpro.cryptography.api.symmetric.SymmetricEncrypter;
import ru.namerpro.cryptography.api.symmetric.expansion.KeyExpansion;
import ru.namerpro.cryptography.utils.Lazy;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.utils.stateless.CryptoGF;

public class Rijndael implements SymmetricEncrypter, KeyExpansion {

    private static final int ROWS_COUNT = 4;
    private final Lazy<byte[][]> sBox;
    private final Lazy<byte[][]> sBoxInv;
    private final byte amountOfRounds;
    private final Triple<Byte, Byte, Byte> shifts;
    private final byte columnsCountInState;
    private final byte columnsCountInKey;
    private final byte[] mixColumnsPoly = { 0x02, 0x01, 0x01, 0x03 };
    private final byte[] mixColumnsPolyInv = { 0x0e, 0x09, 0x0d, 0x0b };
    private final byte moduloWithoutLeadingOne;
    private final byte[][] roundKeys;

    public enum RijndaelBlockSize {
        SZ_128_BITS,
        SZ_192_BITS,
        SZ_256_BITS,
    }

    public Rijndael(RijndaelBlockSize blockSize, byte[] key, byte moduloWithoutLeadingOne) {
        if (!CryptoGF.isIrreducible8(moduloWithoutLeadingOne)) {
            throw new IllegalArgumentException("Irreducible polynomial of power 8 over field of elements in GF(2^8) is required!");
        }

        columnsCountInKey = switch (key.length) {
            case 16 -> 4;
            case 24 -> 6;
            case 32 -> 8;
            default ->
                    throw new IllegalArgumentException("Wrong key size was provided! Supported ones are: 128, 192, 256 bits, - but " + (key.length * 8) + " found.");
        };

        columnsCountInState = switch (blockSize) {
            case SZ_128_BITS -> 4;
            case SZ_192_BITS -> 6;
            case SZ_256_BITS -> 8;
        };

        shifts = switch (columnsCountInKey) {
            case 4, 6 -> Triple.of((byte) 1, (byte) 2, (byte) 3);
            case 8 -> Triple.of((byte) 1, (byte) 3, (byte) 4);
            default -> throw new IllegalArgumentException("Never called. Added to make compiler happy.");
        };

        amountOfRounds = (byte) (Math.max(columnsCountInKey, columnsCountInState) + 6);

        this.moduloWithoutLeadingOne = moduloWithoutLeadingOne;

        sBox = getSBox(moduloWithoutLeadingOne);
        sBoxInv = getSBoxInv(moduloWithoutLeadingOne);

        roundKeys = expandKey(key);
    }

    @Override
    public byte[] encrypt(byte[] block) {
        byte[][] state = toState(block);
        addRoundKey(state, roundKeys[0]);
        for (int i = 1; i < amountOfRounds; ++i) {
            subBytes(state, false);
            shiftRows(state, false);
            mixColumns(state, false);
            addRoundKey(state, roundKeys[i]);
        }
        subBytes(state, false);
        shiftRows(state, false);
        addRoundKey(state, roundKeys[amountOfRounds]);
        return glue(state);
    }

    @Override
    public byte[] decrypt(byte[] block) {
        byte[][] state = toState(block);
        addRoundKey(state, roundKeys[amountOfRounds]);
        for (int i = amountOfRounds - 1; i > 0; --i) {
            shiftRows(state, true);
            subBytes(state, true);
            addRoundKey(state, roundKeys[i]);
            mixColumns(state, true);
        }
        shiftRows(state, true);
        subBytes(state, true);
        addRoundKey(state, roundKeys[0]);
        return glue(state);
    }

    private byte[][] toState(byte[] block) {
        byte[][] state = new byte[4][columnsCountInState];
        for (int i = 0; i < ROWS_COUNT; ++i) {
            for (int j = 0; j < columnsCountInState; ++j) {
                state[i][j] = block[i + ROWS_COUNT * j];
            }
        }
        return state;
    }

    private byte[] glue(byte[][] state) {
        byte[] glued = new byte[columnsCountInState * 4];
        for (int i = 0; i < ROWS_COUNT; ++i) {
            for (int j = 0; j < columnsCountInState; ++j) {
                glued[i + ROWS_COUNT * j] = state[i][j];
            }
        }
        return glued;
    }

    private void subBytes(byte[][] state, boolean isInv) {
        for (int i = 0; i < state.length; ++i) {
            for (int j = 0; j < columnsCountInState; ++j) {
                state[i][j] = isInv ? sBoxInv.get()[(state[i][j] & 0xff) >> 4][state[i][j] & 0xf] : sBox.get()[(state[i][j] & 0xff) >> 4][state[i][j] & 0xf];
            }
        }
    }

    private void shiftRows(byte[][] state, boolean isInv) {
        if (isInv) {
            state[1] = cycledShiftRight(state[1], shifts.getLeft());
            state[2] = cycledShiftRight(state[2], shifts.getMiddle());
            state[3] = cycledShiftRight(state[3], shifts.getRight());
        } else {
            state[1] = cycledShiftLeft(state[1], shifts.getLeft());
            state[2] = cycledShiftLeft(state[2], shifts.getMiddle());
            state[3] = cycledShiftLeft(state[3], shifts.getRight());
        }
    }

    private byte[] cycledShiftLeft(byte[] x, int shift) {
        byte[] shiftedX = new byte[x.length];
        for (int i = 0; i < x.length - shift; ++i) {
            shiftedX[i] = x[shift + i];
        }
        for (int i = x.length - shift; i < shiftedX.length; ++i) {
            shiftedX[i] = x[i - x.length + shift];
        }
        return shiftedX;
    }

    private byte[] cycledShiftRight(byte[] x, int shift) {
        return cycledShiftLeft(x, x.length - shift);
    }

    private void mixColumns(byte[][] state, boolean isInv) {
        for (int i = 0; i < columnsCountInState; ++i) {
            byte[] c = new byte[7];
            for (int j = 0; j < c.length; ++j) {
                int a = Math.min(j, 3);
                int b = Math.max(0, j - 3);
                while (a >= 0 && b <= 3) {
                    c[j] = CryptoGF.add(
                            c[j],
                            CryptoGF.multiply(
                                    state[a][i],
                                    isInv ? mixColumnsPolyInv[b] : mixColumnsPoly[b],
                                    moduloWithoutLeadingOne
                            )
                    );
                    --a;
                    ++b;
                }
            }
            state[0][i] = CryptoGF.add(c[0], c[4]);
            state[1][i] = CryptoGF.add(c[1], c[5]);
            state[2][i] = CryptoGF.add(c[2], c[6]);
            state[3][i] = c[3];
        }
    }

    private void addRoundKey(byte[][] state, byte[] roundKey) {
        for (int i = 0; i < state.length; ++i) {
            for (int j = 0; j < ROWS_COUNT; ++j) {
                state[j][i] ^= roundKey[j + i * ROWS_COUNT];
            }
        }
    }

    private Lazy<byte[][]> getSBox(byte mod) {
        return new Lazy<>(() -> {
            byte[][] innerSBox = new byte[16][16];
            for (byte i = 0; i <= 0x0f; ++i) {
                for (byte j = 0; j <= 0x0f; ++j) {
                    byte b = (byte) ((i << 4) | (j & 0xff));
                    byte bInv = CryptoGF.inverse8(b, mod);
                    innerSBox[i][j] = (byte) ((bInv & 0xff) ^ cycledShiftLeft(bInv, 1) ^ cycledShiftLeft(bInv, 2) ^ cycledShiftLeft(bInv, 3) ^ cycledShiftLeft(bInv, 4) ^ 0x63);
                }
            }
            return innerSBox;
        });
    }

    private Lazy<byte[][]> getSBoxInv(byte mod) {
        return new Lazy<>(() -> {
            byte[][] innerSBoxInv = new byte[16][16];
            for (byte i = 0; i <= 0x0f; ++i) {
                for (byte j = 0; j <= 0x0f; ++j) {
                    byte s = (byte) ((i << 4) | (j & 0xff));
                    byte bInv = (byte) (cycledShiftLeft(s, 1) ^ cycledShiftLeft(s, 3) ^ cycledShiftLeft(s, 6) ^ 0x5);
                    innerSBoxInv[i][j] = CryptoGF.inverse8(bInv, mod);
                }
            }
            return innerSBoxInv;
        });
    }

    private byte cycledShiftLeft(byte x, int y) {
        byte toMove = (byte) (((((1 << y) - 1) << (8 - y)) & (0xff & x)) >>> (8 - y));
        return (byte) ((x << y) | (0xff & toMove));
    }

    @Override
    public byte[][] expandKey(byte[] key) {
        byte[][] expandedKeysStream = new byte[columnsCountInState * (amountOfRounds + 1)][ROWS_COUNT];
        byte[] rCon = getRCon((amountOfRounds + 1) * 2 - 1);
        for (int i = 0; i < columnsCountInKey; ++i) {
            expandedKeysStream[i] = new byte[] {
                    key[i * ROWS_COUNT],
                    key[i * ROWS_COUNT + 1],
                    key[i * ROWS_COUNT + 2],
                    key[i * ROWS_COUNT + 3]
            };
        }
        for (int i = columnsCountInKey; i < columnsCountInState * (amountOfRounds + 1); ++i) {
            byte[] previousColumn = expandedKeysStream[i - 1];
            if (i % columnsCountInKey == 0) {
                previousColumn = cycledShiftLeft(previousColumn, 1);
                for (int j = 0; j < ROWS_COUNT; ++j) {
                    previousColumn[j] = sBox.get()[(previousColumn[j] & 0xff) >> 4][previousColumn[j] & 0xf];
                }
                previousColumn[0] ^= rCon[i / columnsCountInKey - 1];
            } else if (i % columnsCountInKey == 4 && columnsCountInKey > 6) {
                for (int j = 0; j < ROWS_COUNT; ++j) {
                    previousColumn[j] = sBox.get()[(previousColumn[j] & 0xff) >> 4][previousColumn[j] & 0xf];
                }
            }
            expandedKeysStream[i] = Utility.xor(previousColumn, expandedKeysStream[i - columnsCountInKey]);
        }
        return streamToKeys(expandedKeysStream);
    }

    private byte[][] streamToKeys(byte[][] expandedKeysStream) {
        byte[][] expandedKeys = new byte[amountOfRounds + 1][4 * columnsCountInState];
        int roundNumber = 0;
        for (int i = 0; i < expandedKeysStream.length; i += columnsCountInState) {
            for (int j = 0; j < columnsCountInState; ++j) {
                System.arraycopy(expandedKeysStream[i + j], 0, expandedKeys[roundNumber], ROWS_COUNT * j, ROWS_COUNT);
            }
            ++roundNumber;
        }
        return expandedKeys;
    }

    private byte[] getRCon(int n) {
        byte[] rCon = new byte[n];
        for (int i = 0; i < rCon.length; ++i) {
            if (i == 0) {
                rCon[i] = 1;
            } else if ((rCon[i - 1] & 0xff) < 0x80) {
                rCon[i] = (byte) (2 * rCon[i - 1]);
            } else {
                rCon[i] = (byte) ((2 * rCon[i - 1]) ^ 0x11B);
            }
        }
        return rCon;
    }

}
