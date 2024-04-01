package ru.namerpro.cryptography.utils.stateless;

import ru.namerpro.cryptography.utils.Pair;

import java.math.BigInteger;

public class CryptoMath {

    private CryptoMath() {}

    public static int jacobyOf(BigInteger a, BigInteger n) {
        if (n.compareTo(BigInteger.ONE) <= 0 || n.remainder(BigInteger.TWO).equals(BigInteger.ZERO)) {
            throw new IllegalArgumentException("Required odd n > 1, but " + n + " found!");
        }
        a = a.remainder(n);
        int answer = 1;
        BigInteger reminder;
        while (!a.equals(BigInteger.ZERO)) {
            while (a.remainder(BigInteger.TWO).equals(BigInteger.ZERO)) {
                a = a.divide(BigInteger.TWO);
                reminder = n.remainder(BigInteger.valueOf(8));
                if (reminder.equals(BigInteger.valueOf(3)) || reminder.equals(BigInteger.valueOf(5))) {
                    answer = - answer;
                }
            }
            reminder = n;
            n = a;
            a = reminder;
            if (a.remainder(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)) && n.remainder(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3))) {
                answer = -answer;
            }
            a = a.remainder(n);
        }
        return n.intValue() == 1 ? answer : 0;
    }

    public static int legendreOf2(BigInteger a, BigInteger p) {
        return jacobyOf(a, p);
    }

    public static int legendreOf(BigInteger a, BigInteger p) {
        if (a.remainder(p).equals(BigInteger.ZERO)) {
            return 0;
        }
        if (a.equals(BigInteger.ONE)) {
            return 1;
        }
        if (a.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            return legendreOf(a.divide(BigInteger.TWO), p) * (p.multiply(p).subtract(BigInteger.ONE).divide(BigInteger.valueOf(8)).remainder(BigInteger.TWO).equals(BigInteger.ZERO) ? 1 : -1);
        }
        return legendreOf(p.remainder(a), a) * (a.subtract(BigInteger.ONE).multiply(p.subtract(BigInteger.ONE)).divide(BigInteger.valueOf(4)).remainder(BigInteger.TWO).equals(BigInteger.ZERO) ? 1 : -1);
    }

    public static Pair<BigInteger, Pair<BigInteger, BigInteger>> egcd(BigInteger a, BigInteger b) {
        if (a.equals(BigInteger.ZERO)) {
            return Pair.of(b, Pair.of(BigInteger.ZERO, BigInteger.ONE));
        }
        var d = egcd(b.remainder(a), a);
        BigInteger x = d.getValue().getValue().subtract(b.divide(a).multiply(d.getValue().getKey()));
        BigInteger y = d.getValue().getKey();
        return Pair.of(d.getKey(), Pair.of(x, y));
    }

    public static BigInteger gcd(BigInteger x, BigInteger y) {
        while (y.compareTo(BigInteger.ZERO) > 0) {
            x = x.remainder(y);
            x = x.add(y);
            y = x.subtract(y);
            x = x.subtract(y);
        }
        return x;
    }

    public static BigInteger pow(BigInteger x, BigInteger y, BigInteger mod) {
        BigInteger z = BigInteger.ONE;
        while (y.compareTo(BigInteger.ZERO) > 0) {
            if (y.and(BigInteger.ONE).equals(BigInteger.ONE)) {
                z = z.multiply(x).remainder(mod);
            }
            x = x.multiply(x).remainder(mod);
            y = y.shiftRight(1);
        }
        return z;
    }

}
