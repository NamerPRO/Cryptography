package ru.namerpro.cryptography.asymmetricencrypters.rsa.fermatattack;

import ru.namerpro.cryptography.asymmetricencrypters.rsa.RSA;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.RSA.RSAKeyGenerator.PublicKey;
import ru.namerpro.cryptography.utils.Pair;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;
import java.util.Random;

public class FermatAttack {

    public static Pair<BigInteger, BigInteger> attack(PublicKey key) {
        BigInteger p = Utility.bigSqrtN(key.n(), 2).or(BigInteger.ONE);
        while (!key.n().remainder(p).equals(BigInteger.ZERO)) {
            p = p.add(BigInteger.TWO);
        }
        BigInteger q = key.n().divide(p);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        BigInteger d = CryptoMath.egcd(key.e(), phi).getValue().getKey();
        d = d.remainder(phi).add(phi).remainder(phi);

        return Pair.of(d, phi);
    }

    public static void runDemoOfFermatAttack() {
        var numberOne = BigInteger.probablePrime(2048, new Random());
        var numberTwo = numberOne.nextProbablePrime();

        System.out.println("p = " + numberOne);
        System.out.println("q = " + numberTwo);
        System.out.println("q - p = " + numberTwo.subtract(numberOne));

        var phi = numberOne.subtract(BigInteger.ONE).multiply(numberTwo.subtract(BigInteger.ONE));

        System.out.println("phi = " + phi);

        var n = numberOne.multiply(numberTwo);
        var e = Utility.getRandom(BigInteger.valueOf(65537), phi);
        if (e.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            e = e.subtract(BigInteger.ONE);
        }
        while (!CryptoMath.gcd(e, phi).equals(BigInteger.ONE)) {
            e = e.add(BigInteger.TWO);
        }

        System.out.println("e = " + e);
        System.out.println("N = " + n);

        BigInteger d = CryptoMath.egcd(e, phi).getValue().getKey();
        d = d.remainder(phi).add(phi).remainder(phi);

        System.out.println("d = " + d);

        System.out.println("==========================\n");
        var stolen = FermatAttack.attack(new RSA.RSAKeyGenerator.PublicKey(e, n));
        System.out.println("phi = " + stolen.getValue());
        System.out.println("d = " + stolen.getKey());
        System.out.println("phi is correct = " + stolen.getValue().equals(phi));
        System.out.println("d is correct = " + stolen.getKey().equals(d));
        System.out.println("\n==========================");
    }

}
