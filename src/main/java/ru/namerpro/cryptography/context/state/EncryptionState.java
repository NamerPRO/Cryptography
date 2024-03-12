package ru.namerpro.cryptography.context.state;

public sealed interface EncryptionState {

    record Success() implements EncryptionState {}
    record Error(
        Throwable error
    ) implements EncryptionState {}

}
