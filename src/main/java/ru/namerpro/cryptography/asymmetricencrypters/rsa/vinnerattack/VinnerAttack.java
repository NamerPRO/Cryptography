package ru.namerpro.cryptography.asymmetricencrypters.rsa.vinnerattack;

import ru.namerpro.cryptography.asymmetricencrypters.rsa.RSA;
import ru.namerpro.cryptography.asymmetricencrypters.rsa.fermatattack.FermatAttack;
import ru.namerpro.cryptography.utils.Pair;
import ru.namerpro.cryptography.utils.Utility;
import ru.namerpro.cryptography.utils.stateless.CryptoMath;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.ExecutionException;

public class VinnerAttack {

    private static final String vinnerAttackText = "You have been attacked using Vinner scheme! This text is meant to check whether d is found.";

    public static Pair<ArrayList<Pair<BigInteger, BigInteger>>, Pair<BigInteger, BigInteger>> attack(RSA.RSAKeyGenerator.PublicKey key) throws ExecutionException, InterruptedException {
        ArrayList<BigInteger> coefficients = getContinuedFraction(key.e(), key.n());
        ArrayList<Pair<BigInteger, BigInteger>> fractions = new ArrayList<>();
        RSA rsa = new RSA(50);
        fractions.add(Pair.of(coefficients.get(0), BigInteger.ONE));
        for (int i = 1; i < coefficients.size(); ++i) {
            fractions.add(
                    Pair.of(
                            coefficients.get(i).multiply(fractions.get(i - 1).getKey()).add(i == 1 ? BigInteger.ONE : fractions.get(i - 2).getKey()),
                            coefficients.get(i).multiply(fractions.get(i - 1).getValue()).add(i == 1 ? BigInteger.ZERO : fractions.get(i - 2).getValue())
                    )
            );
            BigInteger[] encrypted = rsa.encrypt(vinnerAttackText.getBytes(), key).get();
            try {
                byte[] decrypted = rsa.decrypt(encrypted, new RSA.RSAKeyGenerator.PrivateKey(fractions.get(i).getValue(), key.n())).get();
                if (Arrays.equals(decrypted, vinnerAttackText.getBytes())) {
                    break;
                }
            } catch (Throwable ignored) {}
        }
        System.out.println();
        var lastFraction = fractions.get(fractions.size() - 1);
        BigInteger phi = getPhi(lastFraction, key);
        return Pair.of(fractions, Pair.of(phi, lastFraction.getValue()));
    }

    private static ArrayList<BigInteger> getContinuedFraction(BigInteger e, BigInteger n) {
        ArrayList<BigInteger> coefficients = new ArrayList<>();
        if (e.compareTo(n) < 0) {
            coefficients.add(BigInteger.ZERO);
            e = e.add(n);
            n = e.subtract(n);
            e = e.subtract(n);
        }
        while (!n.equals(BigInteger.ZERO) && e.compareTo(n) >= 0) {
            coefficients.add(e.divide(n));
            e = e.remainder(n).add(n);
            n = e.subtract(n);
            e = e.subtract(n);
        }
        return coefficients;
    }

    private static BigInteger getPhi(Pair<BigInteger, BigInteger> lastFraction, RSA.RSAKeyGenerator.PublicKey key) {
        BigInteger f = key.e().multiply(lastFraction.getValue()).subtract(BigInteger.ONE).divide(lastFraction.getKey());
        BigInteger bCoefficient = key.n().subtract(f).add(BigInteger.ONE);
        BigInteger sqrtD = Utility.bigSqrtN(bCoefficient.multiply(bCoefficient).subtract(BigInteger.valueOf(4).multiply(key.n())), 2);
        BigInteger p = bCoefficient.add(sqrtD).divide(BigInteger.TWO);
        BigInteger q = bCoefficient.subtract(sqrtD).divide(BigInteger.TWO);
        return p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }

    public static void runDemoVinnerAttack() throws ExecutionException, InterruptedException {
        var numberOne = BigInteger.probablePrime(1024, new Random());
        var numberTwo = BigInteger.probablePrime(1024, new Random());

        System.out.println("p = " + numberOne);
        System.out.println("q = " + numberTwo);
        System.out.println("|q - p| = " + numberTwo.subtract(numberOne).abs());

        var phi = numberOne.subtract(BigInteger.ONE).multiply(numberTwo.subtract(BigInteger.ONE));

        System.out.println("phi = " + phi);

        var n = numberOne.multiply(numberTwo);

        var dToValue = Utility.bigSqrtN(n, 4).divide(BigInteger.valueOf(3)).subtract(BigInteger.valueOf(200000));
        var d = Utility.getRandom(BigInteger.valueOf(65537), dToValue);
        if (d.and(BigInteger.ONE).equals(BigInteger.ZERO)) {
            d = d.subtract(BigInteger.ONE);
        }
        while (!CryptoMath.gcd(d, phi).equals(BigInteger.ONE)) {
            d = d.subtract(BigInteger.TWO);
        }

        var e = CryptoMath.egcd(d, phi).getValue().getKey();
        e = e.remainder(phi).add(phi).remainder(phi);

        System.out.println("e = " + e);
        System.out.println("d = " + d);
        System.out.println("N = " + n);

        System.out.println("==========================\n");
        var stolen = VinnerAttack.attack(new RSA.RSAKeyGenerator.PublicKey(e, n));
        System.out.println("phi = " + stolen.getValue().getKey());
        System.out.println("d = " + stolen.getValue().getValue());
        System.out.println("phi is correct = " + stolen.getValue().getKey().equals(phi));
        System.out.println("d is correct = " + stolen.getValue().getValue().equals(d));
        System.out.println("Fractions: ");
        for (var i : stolen.getKey()) {
            System.out.println(i.getKey() + "/" + i.getValue());
        }
        System.out.println("\n==========================");
    }

}
