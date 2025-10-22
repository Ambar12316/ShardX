import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Properties;

public class SharderEncrypt {
    // AES GCM parameters
    private static final String CIPHER = "AES/GCM/NoPadding";
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12; // 96 bits recommended for GCM
    private static final int PBKDF2_ITER = 200_000;
    private static final int SALT_BYTES = 16;

    private static SecureRandom random = new SecureRandom();

    public static void main(String[] args) throws Exception {
        if (args.length < 4) {
            System.out.println("Usage: java SharderEncrypt <input-file> <output-dir> <num-shards> <password>");
            System.out.println("Example: java SharderEncrypt bigfile.zip shards 4 myStrongP@ss");
            return;
        }

        File input = new File(args[0]);
        File outDir = new File(args[1]);
        int shards = Integer.parseInt(args[2]);
        String password = args[3];

        if (!input.exists() || !input.isFile()) {
            System.err.println("Input file doesn't exist or is not a file.");
            return;
        }
        if (!outDir.exists()) {
            if (!outDir.mkdirs()) {
                System.err.println("Failed to create output directory: " + outDir.getAbsolutePath());
                return;
            }
        }
        if (shards <= 0) {
            System.err.println("num-shards must be > 0");
            return;
        }

        long fileSize = input.length();
        long shardSize = (fileSize + shards - 1) / shards; // ceil division

        byte[] salt = new byte[SALT_BYTES];
        random.nextBytes(salt);
        SecretKey aesKey = deriveKeyFromPassword(password.toCharArray(), salt);

        Properties meta = new Properties();
        meta.setProperty("originalName", input.getName());
        meta.setProperty("fileSize", Long.toString(fileSize));
        meta.setProperty("shards", Integer.toString(shards));
        meta.setProperty("salt", Base64.getEncoder().encodeToString(salt));
        meta.setProperty("cipher", CIPHER);
        meta.setProperty("gcmTagBits", Integer.toString(GCM_TAG_BITS));
        meta.setProperty("ivBytes", Integer.toString(IV_BYTES));

        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(input))) {
    byte[] buffer = new byte[8192];
    for (int i = 0; i < shards; i++) {
        long remainingForShard = Math.min(shardSize, fileSize - (long) i * shardSize);
        if (remainingForShard <= 0) {
            remainingForShard = 0;
        }

        String shardName = String.format("%s.shard.%02d", input.getName(), i);
        File shardFile = new File(outDir, shardName);

        // ✅ new IV for every shard
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);

        // ✅ new Cipher instance per shard
        Cipher cipher = Cipher.getInstance(CIPHER);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);

        try (FileOutputStream fos = new FileOutputStream(shardFile);
             BufferedOutputStream bos = new BufferedOutputStream(fos);
             CipherOutputStream cos = new CipherOutputStream(bos, cipher)) {

            long toRead = remainingForShard;
            while (toRead > 0) {
                int r = bis.read(buffer, 0, (int) Math.min(buffer.length, toRead));
                if (r < 0) break;
                cos.write(buffer, 0, r);
                toRead -= r;
            }
        }

        meta.setProperty("shard." + i + ".file", shardName);
        meta.setProperty("shard." + i + ".iv", Base64.getEncoder().encodeToString(iv));
        meta.setProperty("shard." + i + ".encSize", Long.toString(shardFile.length()));
        System.out.println("Wrote shard " + i + " -> " + shardFile.getAbsolutePath());
    }
}


        File metaFile = new File(outDir, input.getName() + ".meta.properties");
        try (OutputStream os = new FileOutputStream(metaFile)) {
            meta.store(os, "Sharding metadata for " + input.getName());
        }
        System.out.println("Wrote metadata: " + metaFile.getAbsolutePath());
        System.out.println("Done. Keep the password safe to decrypt later.");
    }

    private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITER, AES_KEY_BITS);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Simple helper wrapping CipherOutputStream but keeps track of bytes written (optional)
     */
    private static class CipherOutputStreamWithLength extends FilterOutputStream {
        private final Cipher cipher;
        private final ByteArrayOutputStream buf = new ByteArrayOutputStream();

        CipherOutputStreamWithLength(OutputStream out, Cipher cipher) {
            super(out);
            this.cipher = cipher;
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            try {
                byte[] out = cipher.update(b, off, len);
                if (out != null && out.length > 0) super.write(out);
            } catch (Exception e) {
                throw new IOException(e);
            }
        }

        @Override
        public void write(int b) throws IOException {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void close() throws IOException {
            try {
                byte[] finalBytes = cipher.doFinal();
                if (finalBytes != null && finalBytes.length > 0) super.write(finalBytes);
                super.flush();
            } catch (Exception e) {
                throw new IOException("Error finalizing cipher", e);
            } finally {
                super.close();
            }
        }
    }
}