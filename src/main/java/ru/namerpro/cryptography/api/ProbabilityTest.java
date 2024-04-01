package ru.namerpro.cryptography.api;

import java.math.BigInteger;

public interface ProbabilityTest {

    boolean isProbablyPrime(BigInteger value, float probability);

}
