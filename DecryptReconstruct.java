import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.nio.file.Files;
import java.util.Base64;
import java.util.Properties;

public class DecryptReconstruct {
    public static void main(String[] args) throws Exception {
        if (args.length < 3) {
            System.out.println("Usage: java DecryptReconstruct <meta-file> <shards-dir> <output-dir> <password>");
            System.out.println("Example: java DecryptReconstruct bigfile.zip.meta.properties shards reconstructed myStrongP@ss");
            return;
        }

        File metaFile = new File(args[0]);
        File shardsDir = new File(args[1]);
        File outDir = new File(args[2]);
        String password = args.length >= 4 ? args[3] : null;

        if (!metaFile.exists()) {
            System.err.println("metadata file missing: " + metaFile.getAbsolutePath());
            return;
        }
        if (!shardsDir.exists() || !shardsDir.isDirectory()) {
            System.err.println("shards dir doesn't exist or not a directory: " + shardsDir.getAbsolutePath());
            return;
        }
        if (!outDir.exists()) outDir.mkdirs();

        Properties meta = new Properties();
        try (InputStream is = new FileInputStream(metaFile)) {
            meta.load(is);
        }

        String originalName = meta.getProperty("originalName");
        long fileSize = Long.parseLong(meta.getProperty("fileSize"));
        int shards = Integer.parseInt(meta.getProperty("shards"));
        byte[] salt = Base64.getDecoder().decode(meta.getProperty("salt"));
        String cipherName = meta.getProperty("cipher");
        int gcmTagBits = Integer.parseInt(meta.getProperty("gcmTagBits"));
        int ivBytes = Integer.parseInt(meta.getProperty("ivBytes"));

        if (password == null) {
            // Ask on console if not provided
            Console c = System.console();
            if (c != null) {
                char[] pw = c.readPassword("Enter password: ");
                password = new String(pw);
            } else {
                BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                System.out.print("Password: ");
                password = br.readLine();
            }
        }

        SecretKey aesKey = deriveKeyFromPassword(password.toCharArray(), salt);

        File outFile = new File(outDir, originalName + ".reconstructed");
        try (RandomAccessFile raf = new RandomAccessFile(outFile, "rw")) {
            raf.setLength(fileSize); // pre-allocate final size
            long shardSize = (fileSize + shards - 1) / shards;

            byte[] buffer = new byte[8192];
            for (int i = 0; i < shards; i++) {
                String shardFileName = meta.getProperty("shard." + i + ".file");
                String ivB64 = meta.getProperty("shard." + i + ".iv");
                if (shardFileName == null || ivB64 == null) {
                    System.out.println("Missing shard meta for index " + i + ". Skipping.");
                    continue;
                }
                File shardFile = new File(shardsDir, shardFileName);
                if (!shardFile.exists()) {
                    System.err.println("Shard missing: " + shardFile.getAbsolutePath());
                    return;
                }

                byte[] iv = Base64.getDecoder().decode(ivB64);
                Cipher cipher = Cipher.getInstance(cipherName);
                GCMParameterSpec spec = new GCMParameterSpec(gcmTagBits, iv);
                cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);

                long writeOffset = (long) i * shardSize;
                try (InputStream fis = new FileInputStream(shardFile);
                     CipherInputStreamWithEOF cis = new CipherInputStreamWithEOF(fis, cipher);
                ) {
                    int r;
                    long pos = writeOffset;
                    while ((r = cis.read(buffer)) != -1) {
                        raf.seek(pos);
                        raf.write(buffer, 0, r);
                        pos += r;
                    }
                } catch (IOException ex) {
                    System.err.println("Decryption failed for shard " + i + ": " + ex.getMessage());
                    return;
                }
                System.out.println("Decrypted and wrote shard " + i);
            }
        }

        System.out.println("Reconstruction complete: " + outFile.getAbsolutePath());
    }

    private static SecretKey deriveKeyFromPassword(char[] password, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt, 200_000, 256);
        SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = f.generateSecret(spec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }

    /**
     * Simple wrapper to stream decrypted bytes using Cipher.update()/doFinal()
     */
    private static class CipherInputStreamWithEOF extends FilterInputStream {
        private final javax.crypto.Cipher cipher;
        private byte[] one = new byte[1];
        private byte[] finalBytes = null;
        private ByteArrayInputStream finalStream = null;

        protected CipherInputStreamWithEOF(InputStream in, javax.crypto.Cipher cipher) {
            super(in);
            this.cipher = cipher;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            if (finalStream != null) {
                return finalStream.read(b, off, len);
            }

            byte[] inBuf = new byte[len];
            int r = in.read(inBuf, 0, len);
            try {
                if (r > 0) {
                    byte[] out = cipher.update(inBuf, 0, r);
                    if (out != null && out.length > 0) {
                        int toCopy = Math.min(len, out.length);
                        System.arraycopy(out, 0, b, off, toCopy);
                        // if out.length > len, we ignore extra (unlikely because sizes aligned)
                        return toCopy;
                    } else {
                        return 0;
                    }
                } else {
                    // EOF on underlying stream: finalize cipher
                    finalBytes = cipher.doFinal();
                    finalStream = new ByteArrayInputStream(finalBytes != null ? finalBytes : new byte[0]);
                    return finalStream.read(b, off, len);
                }
            } catch (Exception e) {
                throw new IOException("Cipher error", e);
            }
        }

        @Override
        public int read() throws IOException {
            int r = read(one, 0, 1);
            return r == -1 ? -1 : (one[0] & 0xff);
        }
    }
}
