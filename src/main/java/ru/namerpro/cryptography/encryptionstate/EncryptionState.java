package ru.namerpro.cryptography.encryptionstate;

public sealed interface EncryptionState {

    record Success() implements EncryptionState {}
    record Error(
        Throwable error
    ) implements EncryptionState {}

}
