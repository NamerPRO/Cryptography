package ru.namerpro.cryptography.utils;

import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
@AllArgsConstructor
@EqualsAndHashCode
public class Pair<T, U> {

    private T key;
    private U value;

    public static <T, U> Pair<T, U> of(T first, U second) {
        return new Pair<>(first, second);
    }

}