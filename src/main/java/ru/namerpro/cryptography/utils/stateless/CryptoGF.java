package ru.namerpro.cryptography.utils.stateless;

import org.apache.commons.lang3.ArrayUtils;
import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.util.ArrayList;

public class CryptoGF {

    private CryptoGF() {}

    public static byte add(byte x, byte y) {
        return (byte) (x ^ y);
    }

    public static byte multiply(byte x, byte y, byte mod) {
        char mul = 0;
        while (x != 0) {
            int bitIndex = getPolynomialPower(x & 0xff);
            mul ^= (char) ((0xff & y) << bitIndex);
            x ^= (byte) (1 << bitIndex);
        }
        return reminder8(mul, mod);
    }

    public static byte reminder8(char x, byte mod) {
        if (mod == 0) {
            throw new ArithmeticException("Reminder by 0 is not allowed!");
        }
        if (x == 0) {
            return 0;
        }
        int maxModPolyPow = 8;
        int xPolyPow = getPolynomialPower(x & 0xffff);
        while (xPolyPow >= maxModPolyPow) {
            x ^= (char) ((mod & 0xff | (1 << 8)) << (xPolyPow - maxModPolyPow));
            xPolyPow = getPolynomialPower(x & 0xffff);
        }
        return (byte) x;
    }

    public static byte reminder(char x, byte mod) {
        if (mod == 0) {
            throw new ArithmeticException("Reminder by 0 is not allowed!");
        }
        if (x == 0 || mod == 1) {
            return 0;
        }
        int maxModPolyPow = getPolynomialPower(mod & 0xff);
        int xPolyPow = getPolynomialPower(x & 0xffff);
        while (xPolyPow >= maxModPolyPow) {
            x ^= (char) ((mod & 0xff) << (xPolyPow - maxModPolyPow));
            xPolyPow = getPolynomialPower(x & 0xffff);
        }
        return (byte) x;
    }

    public static byte divide(byte x, byte y) {
        if (y == 0) {
            throw new ArithmeticException("Division by 0 is not allowed!");
        }
        if (x == 0) {
            return 0;
        }
        int maxYPolyPow = getPolynomialPower(y & 0xff);
        int xPolyPow = getPolynomialPower(x & 0xff);
        byte z = 0;
        while (xPolyPow >= maxYPolyPow) {
            x ^= (byte) (y << (xPolyPow - maxYPolyPow));
            z ^= (byte) (1 << (xPolyPow - maxYPolyPow));
            xPolyPow = getPolynomialPower(x & 0xff);
        }
        return z;
    }

    public static byte inverse8(byte x, byte mod) {
        if (mod == 0) {
            throw new ArithmeticException("Modulo cannot be 0!");
        }
        return x == 0 ? 0 : pow(x, 254, mod);
    }

    public static byte pow(byte x, int y, byte mod) {
        byte z = 1;
        while (y != 0) {
            if ((y & 1) == 1) {
                z = multiply(z, x, mod);
            }
            x = multiply(x, x, mod);
            y >>>= 1;
        }
        return z;
    }

    public static boolean isIrreducible8(byte x) {
        for (byte i = 2; i < (1 << 5); ++i) {
            if (reminder((char) ((1 << 8) | (x & 0xff)), i) == 0) {
                return false;
            }
        }
        return true;
    }

    public static byte[] getIrreduciblePolynomials8() {
        ArrayList<Byte> list = new ArrayList<>();
        for (char i = 0; i < (1 << 8); ++i) {
            if (isIrreducible8((byte) i)) {
                list.add((byte) i);
            }
        }
        return ArrayUtils.toPrimitive(list.toArray(Byte[]::new));
    }

    public static BigInteger reminderN(BigInteger x, BigInteger mod) {
        if (mod.compareTo(BigInteger.ZERO) <= 0 || x.compareTo(BigInteger.ZERO) < 0) {
            throw new ArithmeticException("Reminder or number < 0 number is not allowed!");
        }
        if (x.equals(BigInteger.ZERO) || mod.equals(BigInteger.ONE)) {
            return BigInteger.ZERO;
        }
        int maxModPolyPow = getPolynomialPower(mod);
        int xPolyPow = getPolynomialPower(x);
        while (xPolyPow >= maxModPolyPow) {
            x = x.xor(mod.shiftLeft(xPolyPow - maxModPolyPow));
            xPolyPow = getPolynomialPower(x);
        }
        return x;
    }

    public static BigInteger divideN(BigInteger x, BigInteger y) {
        if (y.equals(BigInteger.ZERO)) {
            throw new ArithmeticException("Division by 0 is not allowed!");
        }
        if (x.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }
        int maxYPolyPow = getPolynomialPower(y);
        int xPolyPow = getPolynomialPower(x);
        BigInteger z = BigInteger.ZERO;
        while (xPolyPow >= maxYPolyPow) {
            x = x.xor(y.shiftLeft(xPolyPow - maxYPolyPow));
            z = z.xor(BigInteger.ONE.shiftLeft(xPolyPow - maxYPolyPow));
            xPolyPow = getPolynomialPower(x);
        }
        return z;
    }

    public static BigInteger[] getDecomposition(BigInteger x, BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) <= 0) {
            throw new IllegalArgumentException("n must be > 1");
        }
        int maxPolyPow = getPolynomialPower(x);
        int toPolyPow = maxPolyPow / 2 + 1;
        ArrayList<BigInteger> list = new ArrayList<>();
        for (BigInteger i = BigInteger.TWO; i.compareTo(BigInteger.ONE.shiftLeft (toPolyPow)) < 0; i = i.add(BigInteger.ONE)) {
            while (reminderN(x, i).compareTo(BigInteger.ZERO) == 0) {
                x = divideN(x, i);
                list.add(i);
            }
        }
        if (x.compareTo(BigInteger.ONE) > 0) {
            list.add(x);
        }
        BigInteger[] primitiveList = new BigInteger[list.size()];
        for (int i = 0; i < primitiveList.length; ++i) {
            primitiveList[i] = list.get(i);
        }
        return primitiveList;
    }

    public static int getPolynomialPower(long x) {
        return x == 0 ? 0 : Long.numberOfTrailingZeros(Long.highestOneBit(x));
    }

    public static int getPolynomialPower(@NotNull BigInteger x) {
        int power = -1;
        while (!x.equals(BigInteger.ZERO)) {
            ++power;
            x = x.shiftRight(1);
        }
        return Math.max(power, 0);
    }

}
