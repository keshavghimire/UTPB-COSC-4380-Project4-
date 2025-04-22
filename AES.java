import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;

public class AES {
    private final int[][] keySchedule; // Stores the expanded key
    private final boolean debug; // Debug flag for detailed output
    private static final int BLOCK_SIZE = 16; // 128 bits
    private static final int Nk = 4; // Number of 32-bit words in key (128/32 = 4)
    private static final int Nb = 4; // Number of columns in state (128/32 = 4)
    private static final int Nr = 10; // Number of rounds for 128-bit key

    private static final HashMap<Integer, Integer> RC = new HashMap<>();
    static {
        RC.put(1, 0x01);
        RC.put(2, 0x02);
        RC.put(3, 0x04);
        RC.put(4, 0x08);
        RC.put(5, 0x10);
        RC.put(6, 0x20);
        RC.put(7, 0x40);
        RC.put(8, 0x80);
        RC.put(9, 0x1B);
        RC.put(10, 0x36);
    }

    public AES(String key, boolean debug) {
        this.debug = debug;
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        if (keyBytes.length != 16) {
            throw new IllegalArgumentException("Key must be 16 bytes long");
        }
        keySchedule = keyExpansion(keyBytes);
        if (debug) {
            printKeySchedule();
        }
    }

    public String encrypt(String plaintext, boolean cbcMode) {
        byte[] plaintextBytes = plaintext.getBytes(StandardCharsets.UTF_8);
        byte[] padded = pad(plaintextBytes);
        byte[] iv = cbcMode ? generateIV() : new byte[0];
        byte[] ciphertext = new byte[cbcMode ? padded.length + BLOCK_SIZE : padded.length];

        if (debug) {
            System.out.println("Plaintext: " + bytesToHex(plaintextBytes));
        }

        if (cbcMode) {
            System.arraycopy(iv, 0, ciphertext, 0, BLOCK_SIZE);
        }

        byte[] previous = iv.length > 0 ? iv : new byte[BLOCK_SIZE];
        for (int i = 0; i < padded.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(padded, i, i + BLOCK_SIZE);
            if (cbcMode) {
                block = xor(block, previous);
            }
            int[][] state = bytesToState(block);
            state = cipher(state, true);
            byte[] encryptedBlock = stateToBytes(state);
            System.arraycopy(encryptedBlock, 0, ciphertext, cbcMode ? i + BLOCK_SIZE : i, BLOCK_SIZE);
            previous = encryptedBlock;
        }

        String result = bytesToHex(ciphertext);
        if (debug) {
            System.out.println("Ciphertext: " + result);
        }
        return result;
    }

    public String decrypt(String ciphertext, boolean cbcMode) {
        byte[] ciphertextBytes = hexToBytes(ciphertext);
        if (ciphertextBytes.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Invalid ciphertext length");
        }

        byte[] iv = cbcMode ? Arrays.copyOfRange(ciphertextBytes, 0, BLOCK_SIZE) : new byte[0];
        byte[] data = cbcMode ? Arrays.copyOfRange(ciphertextBytes, BLOCK_SIZE, ciphertextBytes.length) : ciphertextBytes;
        byte[] decrypted = new byte[data.length];

        if (debug) {
            System.out.println("Ciphertext: " + ciphertext);
        }

        byte[] previous = iv.length > 0 ? iv : new byte[BLOCK_SIZE];
        for (int i = 0; i < data.length; i += BLOCK_SIZE) {
            byte[] block = Arrays.copyOfRange(data, i, i + BLOCK_SIZE);
            int[][] state = bytesToState(block);
            state = cipher(state, false);
            byte[] decryptedBlock = stateToBytes(state);
            if (cbcMode) {
                decryptedBlock = xor(decryptedBlock, previous);
            }
            System.arraycopy(decryptedBlock, 0, decrypted, i, BLOCK_SIZE);
            previous = block;
        }

        byte[] unpadded = unpad(decrypted);
        String result = new String(unpadded, StandardCharsets.UTF_8);
        if (debug) {
            System.out.println("Plaintext: " + bytesToHex(unpadded));
        }
        return result;
    }

    private int[][] cipher(int[][] state, boolean encryptMode) {
        int[][] inputState = new int[4][4];
        for (int r = 0; r < 4; r++) {
            inputState[r] = state[r].clone();
        }

        if (encryptMode) {
            if (debug) {
                System.out.println("Round 0 Input: ");
                printState(inputState);
            }

            addRoundKey(state, getRoundKey(0));
            if (debug) {
                System.out.println("Round 0 AddRoundKey: ");
                printState(getRoundKey(0));
                printState(state);
            }

            for (int round = 1; round < Nr; round++) {
                if (debug) {
                    System.out.println("Round " + round + " Input: ");
                    printState(state);
                }

                subBytes(state, true);
                if (debug) {
                    System.out.println("Round " + round + " SubBytes: ");
                    printState(state);
                }

                shiftRows(state, true);
                if (debug) {
                    System.out.println("Round " + round + " ShiftRows: ");
                    printState(state);
                }

                mixColumns(state, true);
                if (debug) {
                    System.out.println("Round " + round + " MixColumns: ");
                    printState(state);
                }

                addRoundKey(state, getRoundKey(round));
                if (debug) {
                    System.out.println("Round " + round + " AddRoundKey: ");
                    printState(getRoundKey(round));
                    printState(state);
                }
            }

            if (debug) {
                System.out.println("Round " + Nr + " Input: ");
                printState(state);
            }

            subBytes(state, true);
            if (debug) {
                System.out.println("Round " + Nr + " SubBytes: ");
                printState(state);
            }

            shiftRows(state, true);
            if (debug) {
                System.out.println("Round " + Nr + " ShiftRows: ");
                printState(state);
            }

            addRoundKey(state, getRoundKey(Nr));
            if (debug) {
                System.out.println("Round " + Nr + " AddRoundKey: ");
                printState(getRoundKey(Nr));
                printState(state);
            }
        } else {
            if (debug) {
                System.out.println("Round 0 Input: ");
                printState(inputState);
            }

            addRoundKey(state, getRoundKey(Nr));
            if (debug) {
                System.out.println("Round 0 AddRoundKey: ");
                printState(getRoundKey(Nr));
                printState(state);
            }

            shiftRows(state, false);
            if (debug) {
                System.out.println("Round 0 InvShiftRows: ");
                printState(state);
            }

            subBytes(state, false);
            if (debug) {
                System.out.println("Round 0 InvSubBytes: ");
                printState(state);
            }

            for (int round = 1; round < Nr; round++) {
                if (debug) {
                    System.out.println("Round " + round + " Input: ");
                    printState(state);
                }

                addRoundKey(state, getRoundKey(Nr - round));
                if (debug) {
                    System.out.println("Round " + round + " AddRoundKey: ");
                    printState(getRoundKey(Nr - round));
                    printState(state);
                }

                mixColumns(state, false);
                if (debug) {
                    System.out.println("Round " + round + " InvMixColumns: ");
                    printState(state);
                }

                shiftRows(state, false);
                if (debug) {
                    System.out.println("Round " + round + " InvShiftRows: ");
                    printState(state);
                }

                subBytes(state, false);
                if (debug) {
                    System.out.println("Round " + round + " InvSubBytes: ");
                    printState(state);
                }
            }

            if (debug) {
                System.out.println("Round " + Nr + " Input: ");
                printState(state);
            }

            addRoundKey(state, getRoundKey(0));
            if (debug) {
                System.out.println("Round " + Nr + " AddRoundKey: ");
                printState(getRoundKey(0));
                printState(state);
            }
        }

        return state;
    }

    private int[][] keyExpansion(byte[] key) {
        int[][] w = new int[4 * (Nr + 1)][4];
        for (int i = 0; i < Nk; i++) {
            for (int j = 0; j < 4; j++) {
                w[i][j] = key[4 * i + j] & 0xFF;
            }
        }

        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            int[] temp = w[i - 1];
            if (i % Nk == 0) {
                temp = xor(subWord(rotWord(temp)), rcon(i / Nk));
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = xor(w[i - Nk], temp);
        }
        return w;
    }

    private int[] rotWord(int[] word) {
        int[] rot = new int[4];
        rot[0] = word[1];
        rot[1] = word[2];
        rot[2] = word[3];
        rot[3] = word[0];
        return rot;
    }

    private int[] subWord(int[] word) {
        int[] result = new int[4];
        for (int i = 0; i < 4; i++) {
            result[i] = SBox.sbox(word[i]);
        }
        return result;
    }

    private int[] rcon(int i) {
        return new int[]{RC.get(i), 0, 0, 0};
    }

    private int[] xor(int[] a, int[] b) {
        int[] result = new int[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = a[i] ^ b[i];
        }
        return result;
    }

    private void subBytes(int[][] state, boolean mode) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] = mode ? SBox.sbox(state[r][c]) : SBox.invSbox(state[r][c]);
            }
        }
    }

    private void shiftRows(int[][] state, boolean mode) {
        for (int r = 1; r < 4; r++) {
            int[] temp = new int[4];
            for (int c = 0; c < 4; c++) {
                temp[c] = mode ? state[r][(c + r) % 4] : state[r][(c - r + 4) % 4];
            }
            state[r] = temp;
        }
    }

    private void mixColumns(int[][] state, boolean mode) {
        for (int c = 0; c < 4; c++) {
            int[] col = new int[]{state[0][c], state[1][c], state[2][c], state[3][c]};
            int[] result = mode ? MixCols.mix(col) : MixCols.invMix(col);
            for (int r = 0; r < 4; r++) {
                state[r][c] = result[r];
            }
        }
    }

    private void addRoundKey(int[][] state, int[][] roundKey) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                state[r][c] ^= roundKey[r][c];
            }
        }
    }

    private int[][] getRoundKey(int round) {
        int[][] key = new int[4][4];
        for (int i = 0; i < 4; i++) {
            key[i] = keySchedule[round * Nb + i];
        }
        return key;
    }

    private byte[] pad(byte[] input) {
        int paddingLength = BLOCK_SIZE - (input.length % BLOCK_SIZE);
        if (paddingLength == 0) {
            paddingLength = BLOCK_SIZE; // Add a full block of padding if input is multiple of block size
        }
        byte[] padded = new byte[input.length + paddingLength];
        System.arraycopy(input, 0, padded, 0, input.length);
        for (int i = input.length; i < padded.length; i++) {
            padded[i] = (byte) paddingLength;
        }
        return padded;
    }

    private byte[] unpad(byte[] input) {
        if (input.length == 0 || input.length % BLOCK_SIZE != 0) {
            throw new IllegalArgumentException("Invalid input length for unpadding");
        }
        int paddingLength = input[input.length - 1] & 0xFF;
        if (paddingLength < 1 || paddingLength > BLOCK_SIZE) {
            throw new IllegalArgumentException("Invalid padding");
        }
        // Verify padding bytes
        for (int i = input.length - paddingLength; i < input.length; i++) {
            if ((input[i] & 0xFF) != paddingLength) {
                throw new IllegalArgumentException("Invalid padding bytes");
            }
        }
        return Arrays.copyOfRange(input, 0, input.length - paddingLength);
    }

    private byte[] generateIV() {
        byte[] iv = new byte[BLOCK_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        return result;
    }

    private int[][] bytesToState(byte[] block) {
        int[][] state = new int[4][4];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i % 4][i / 4] = block[i] & 0xFF;
        }
        return state;
    }

    private byte[] stateToBytes(int[][] state) {
        byte[] block = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            block[i] = (byte) state[i % 4][i / 4];
        }
        return block;
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4) + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    private void printState(int[][] state) {
        for (int r = 0; r < 4; r++) {
            for (int c = 0; c < 4; c++) {
                System.out.print(String.format("%02x ", state[r][c]));
            }
            System.out.println();
        }
        System.out.println();
    }

    private void printKeySchedule() {
        System.out.println("Key Schedule:");
        for (int i = 0; i < keySchedule.length; i++) {
            System.out.print("w[" + i + "]: ");
            for (int j = 0; j < 4; j++) {
                System.out.print(String.format("%02x ", keySchedule[i][j]));
            }
            System.out.println();
        }
        System.out.println();
    }

    public static void main(String[] args) {
        String key = "Thats my Kung Fu"; // 16 bytes
        AES aes = new AES(key, true);
        String plaintext = "Two One Nine Two";
        String ciphertext = aes.encrypt(plaintext, false); // ECB mode
        String decrypted = aes.decrypt(ciphertext, false);
        System.out.println("Decrypted: " + decrypted);
    }
}