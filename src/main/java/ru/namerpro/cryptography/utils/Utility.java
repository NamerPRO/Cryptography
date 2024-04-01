package ru.namerpro.cryptography.utils;

import lombok.SneakyThrows;

import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.Future;

public class Utility {

    public static byte[][] splitToBlocks(byte[] src, int blockSize) {
        int blocksCount = src.length / blockSize;
        byte[][] splitSrc = new byte[blocksCount][blockSize];
        for (int i = 0; i < blocksCount; ++i) {
            for (int j = 0; j < blockSize; ++j) {
                splitSrc[i][j] = src[i * blockSize + j];
            }
        }
        return splitSrc;
    }

    public static byte[] queryResult(List<Pair<Integer, Future<byte[]>>> futures, int blockSize, int textSize) {
        return (byte[]) queryResult(futures, blockSize, textSize, false);
    }

    @SneakyThrows
    public static Object queryResult(List<Pair<Integer, Future<byte[]>>> futures, int blockSize, int textSize, boolean isSplit) {
        Object result = isSplit ? new byte[futures.size()][] : new byte[textSize];
        var it = futures.listIterator();
        while (!futures.isEmpty()) {
            var currentData = it.next();
            int currentIndex = currentData.getKey();
            var currentFuture = currentData.getValue();
            if (currentFuture.isDone()) {
                var response = currentFuture.get();
                if (isSplit) {
                    ((byte[][]) result)[currentIndex] = response;
                } else {
                    for (int i = 0; i < blockSize; ++i) {
                        ((byte[]) result)[currentIndex * blockSize + i] = response[i];
                    }
                }
                it.remove();
            }
            if (!it.hasNext()) {
                it = futures.listIterator();
            }
        }
        return result;
    }

    public static byte[] xor(byte[] left, byte[] right) {
        byte[] result = new byte[Math.max(left.length, right.length)];
        if (left.length < right.length) {
            for (int i = 0; i < right.length - left.length; ++i) {
                result[i] = right[i];
            }
            int j = right.length - left.length;
            for (int i = j; i < result.length; ++i) {
                result[i] = (byte) (left[i - j] ^ right[i]);
            }
        } else if (left.length > right.length) {
            for (int i = 0; i < left.length - right.length; ++i) {
                result[i] = left[i];
            }
            int j = left.length - right.length;
            for (int i = j; i < result.length; ++i) {
                result[i] = (byte) (left[i] ^ right[i - j]);
            }
        } else {
            for (int i = 0; i < result.length; ++i) {
                result[i] = (byte) (left[i] ^ right[i]);
            }
        }
        return result;
    }

    public static byte[] toByteArray(String text) {
        return text.getBytes();
    }

    public static byte[] toByteArray(String text, Charset charset) {
        return text.getBytes(charset);
    }

    public static byte[] toByteArray(int number) {
        return new byte[] {
                (byte) (number >>> 24),
                (byte) (number >>> 16),
                (byte) (number >>> 8),
                (byte) number
        };
    }

    public static byte[] toByteArray(long number) {
        return new byte[] {
                (byte) (number >>> 56),
                (byte) (number >>> 48),
                (byte) (number >>> 40),
                (byte) (number >>> 32),
                (byte) (number >>> 24),
                (byte) (number >>> 16),
                (byte) (number >>> 8),
                (byte) number
        };
    }

    public static byte[] toByteArray(BigInteger number) {
        byte[] out = number.toByteArray();
        int extra = out[0] == 0 ? (out.length == 1 ? 0 : 1) : 0;
        if (extra == 0) {
            return out;
        }
        byte[] out2 = new byte[out.length - 1];
        System.arraycopy(out, 1, out2, 0, out.length - 1);
        return out2;
    }

    public static byte[] glue(byte[] left, byte[] right) {
        byte[] out = new byte[left.length + right.length];
        System.arraycopy(left, 0, out, 0, left.length);
        System.arraycopy(right, 0, out, left.length, right.length);
        return out;
    }

    public static BigInteger getRandom(BigInteger from, BigInteger to) {
        BigInteger random;
        do {
            random = new BigInteger(to.bitLength(), new SecureRandom());
        } while (random.compareTo(from) < 0 || random.compareTo(to) >= 0);
        return random;
    }

    public static BigInteger bigSqrtN(BigInteger x, int n) {
        BigInteger left = BigInteger.ZERO;
        BigInteger right = x;
        while (right.subtract(left).compareTo(BigInteger.ONE) > 0) {
            BigInteger mid = left.add(right).divide(BigInteger.TWO);
            int cmp = mid.pow(n).compareTo(x);
            if (cmp > 0) {
                right = mid;
            } else if (cmp < 0) {
                left = mid;
            } else {
                return mid;
            }
        }
        return left;
    }

}
