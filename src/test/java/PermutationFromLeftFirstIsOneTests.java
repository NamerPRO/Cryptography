import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;
import ru.namerpro.cryptography.permutaion.Permutation;

public class PermutationFromLeftFirstIsOneTests {

    @Test
    public void permutationFromLeftFirstIsOneTestOne() {
        byte[] input = Permutation.toByteArray(181);
        int[] pBlock = { 1, 2, 4, 8, 3, 7, 6, 5 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(186), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestTwo() {
        byte[] input = Permutation.toByteArray(317826);
        int[] pBlock = { 7, 9, 4, 5, 2, 8, 1, 1 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(183), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestThree() {
        byte[] input = Permutation.toByteArray(317826);
        int[] pBlock = { 13, 14, 15, 16, 17 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(0), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestFour() {
        byte[] input = Permutation.toByteArray(317826);
        int[] pBlock = { 1, 4, 2, 3, 6, 5, 7, 9, 8 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(397), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestFive() {
        byte[] input = Permutation.toByteArray(1);
        int[] pBlock = { 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(16777215), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestSix() {
        byte[] input = Permutation.toByteArray(2);
        int[] pBlock = { 1, 2, 1 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(5), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestSeven() {
        byte[] input = Permutation.toByteArray(2);
        int[] pBlock = { 2, 1, 2 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(2), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestEight() {
        byte[] input = Permutation.toByteArray(32992);
        int[] pBlock = { 16 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(0), output);
    }

    @Test
    public void permutationFromLeftFirstIsOneTestNine() {
        byte[] input = Permutation.toByteArray(32992);
        int[] pBlock = { 1, 2, 3, 17, 4 };

        Assertions.assertThrows(IndexOutOfBoundsException.class, () -> Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE));
    }

    @Test
    public void permutationFromLeftFirstIsOneTestTen() {
        byte[] input = Permutation.toByteArray(32769);
        int[] pBlock = { 16 };

        byte[] output = Permutation.rearrange(input, pBlock, Permutation.Rule.FROM_LEFT_FIRST_IS_ONE);
        Assertions.assertArrayEquals(Permutation.toByteArray(1), output);
    }

}
