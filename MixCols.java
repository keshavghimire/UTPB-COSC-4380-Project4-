public class MixCols {
    private static final int[] mc2 = {2, 3, 1, 1};
    private static final int[] mc3 = {3, 1, 1, 2};
    private static final int[] mc9 = {9, 14, 11, 13};
    private static final int[] mc11 = {11, 13, 9, 14};
    private static final int[] mc13 = {13, 9, 14, 11};
    private static final int[] mc14 = {14, 11, 13, 9};

    public static int[] mix(int[] col) {
        int[] result = new int[4];
        result[0] = (gfMul(col[0], 2) ^ gfMul(col[1], 3) ^ col[2] ^ col[3]) & 0xFF;
        result[1] = (col[0] ^ gfMul(col[1], 2) ^ gfMul(col[2], 3) ^ col[3]) & 0xFF;
        result[2] = (col[0] ^ col[1] ^ gfMul(col[2], 2) ^ gfMul(col[3], 3)) & 0xFF;
        result[3] = (gfMul(col[0], 3) ^ col[1] ^ col[2] ^ gfMul(col[3], 2)) & 0xFF;
        return result;
    }

    public static int[] invMix(int[] col) {
        int[] result = new int[4];
        result[0] = (gfMul(col[0], 14) ^ gfMul(col[1], 11) ^ gfMul(col[2], 13) ^ gfMul(col[3], 9)) & 0xFF;
        result[1] = (gfMul(col[0], 9) ^ gfMul(col[1], 14) ^ gfMul(col[2], 11) ^ gfMul(col[3], 13)) & 0xFF;
        result[2] = (gfMul(col[0], 13) ^ gfMul(col[1], 9) ^ gfMul(col[2], 14) ^ gfMul(col[3], 11)) & 0xFF;
        result[3] = (gfMul(col[0], 11) ^ gfMul(col[1], 13) ^ gfMul(col[2], 9) ^ gfMul(col[3], 14)) & 0xFF;
        return result;
    }

    private static int gfMul(int a, int b) {
        int p = 0;
        int hiBitSet;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1) {
                p ^= a;
            }
            hiBitSet = a & 0x80;
            a <<= 1;
            if (hiBitSet != 0) {
                a ^= 0x1B; // AES polynomial x^8 + x^4 + x^3 + x + 1
            }
            b >>= 1;
            a &= 0xFF;
        }
        return p & 0xFF;
    }
}