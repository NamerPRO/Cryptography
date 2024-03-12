package ru.namerpro.cryptography.permutaion;

import java.math.BigInteger;
import java.util.Arrays;

public class Permutation {

    public enum  Rule {
        FROM_LEFT_FIRST_IS_ZERO,
        FROM_LEFT_FIRST_IS_ONE,
        FROM_RIGHT_FIRST_IS_ZERO,
        FROM_RIGHT_FIRST_IS_ONE
    }

    private static int getLeadingOnePosition(byte number) {
        return number == 0 ? -1 : Integer.numberOfTrailingZeros(Integer.highestOneBit(0xFF & number));
    }

    @Deprecated
    public static byte[] toByteArray(long input) {
        byte[] output = BigInteger.valueOf(input).toByteArray();
        if (output[0] == 0 && output.length > 1) {
            return Arrays.copyOfRange(output, 1, output.length);
        }
        return output;
    }

    public static byte[] rearrange(byte[] input, int[] pBlock, Rule rule) {
        return rearrange(input, (byte) 0, pBlock, rule);
    }

    public static byte[] rearrange(byte[] input, byte numberOfLeadingZerosIncludedInZeroElementOfArray, int[] pBlock, Rule rule) {
        int bitsInOutputCount = pBlock.length;
        int outputArraySize = bitsInOutputCount / 8;
        int firstOutputBlockSize = bitsInOutputCount % 8;
        if (firstOutputBlockSize > 0) {
            ++outputArraySize;
        }
        byte leadingPosition = (byte) (getLeadingOnePosition(input[0]) + numberOfLeadingZerosIncludedInZeroElementOfArray + (input.length == 1 && input[0] == 0 ? 1 : 0));
        byte[] output = new byte[outputArraySize];
        int totalBitsCount = 8 * (input.length - 1) + leadingPosition + 1;

        for (int i = 0; i < bitsInOutputCount; ++i) {
            int bitIndex = pBlock[i];

            if (rule == Rule.FROM_LEFT_FIRST_IS_ONE || rule == Rule.FROM_RIGHT_FIRST_IS_ONE) {
                --bitIndex;
            }

            if (bitIndex >= totalBitsCount || bitIndex < 0) {
                throw new IndexOutOfBoundsException("Wrong pBlock: one of numbers of pBlock is beyond number length!");
            }

            byte takenBit = getTakenBit(input, rule, bitIndex, leadingPosition);

            if (i < firstOutputBlockSize) {
                output[0] |= (byte) (takenBit << (firstOutputBlockSize - i - 1));
            } else {
                output[(i - firstOutputBlockSize) / 8 + (firstOutputBlockSize > 0 ? 1 : 0)] |= (byte) (takenBit << (7 - (i - firstOutputBlockSize) % 8));
            }
        }

        return output;
    }

    private static byte getTakenBit(byte[] input, Rule rule, int bitIndex, int leadingPosition) {
        byte takenBit;
        if (rule == Rule.FROM_LEFT_FIRST_IS_ONE || rule == Rule.FROM_LEFT_FIRST_IS_ZERO) {
            if (bitIndex <= leadingPosition) {
                takenBit = (byte) ((input[0] & (1 << (leadingPosition - bitIndex))) >> (leadingPosition - bitIndex));
            } else {
                int castedIndex = bitIndex - leadingPosition - 1;
                takenBit = (byte) ((input[castedIndex / 8 + 1] & (1 << (7 - castedIndex % 8))) >> (7 - castedIndex % 8));
            }
        } else {
            takenBit = (byte) ((input[input.length - bitIndex / 8 - 1] & (1 << (bitIndex % 8))) >> (bitIndex % 8));
        }
        return takenBit;
    }

}
