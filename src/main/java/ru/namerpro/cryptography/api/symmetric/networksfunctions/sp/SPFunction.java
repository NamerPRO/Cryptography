package ru.namerpro.cryptography.api.symmetric.networksfunctions.sp;

public interface SPFunction<T> {

    T runSPFunctionForward(T state, int roundNumber);
    T runSPFunctionReversed(T state, int roundNumber);

}
