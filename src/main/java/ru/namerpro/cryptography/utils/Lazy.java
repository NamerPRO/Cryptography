package ru.namerpro.cryptography.utils;

import java.util.function.Supplier;

public class Lazy<T> implements Supplier<T> {

    private final Supplier<T> supplier;
    private volatile T value; // NOSONAR

    public Lazy(Supplier<T> supplier) {
        this.supplier = supplier;
    }

    @Override
    public synchronized T get() {
        if (value == null) {
            value = supplier.get();
        }
        return value;
    }

}
