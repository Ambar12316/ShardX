# ShardX
A lightweight Java-based application that securely **encrypts files using AES-GCM** and **splits them into multiple encrypted shards** for distributed or secure storage.   It also includes a companion **decryption tool** to reconstruct the original file from the shards.

# Notes to be considered
Password-based key: This uses PBKDF2WithHmacSHA256 with 200,000 iterations and a per-file random salt stored in the metadata. You must keep the password secret — losing it means you cannot decrypt.

AES-GCM: Provides confidentiality and integrity. If any shard is tampered with, decryption will fail.

Sharding approach: This implementation splits the file into contiguous chunks (shard 0 = first N bytes, shard 1 = next N bytes, ...). That's simple and efficient. If you want striping (round-robin), or erasure coding (Reed-Solomon) for redundancy, that's a more advanced change — I can add it.

Metadata: Stored in a simple properties file to avoid external libs. It includes IVs (base64) and salt (base64). Keep the metadata file with shards.

Large files: Uses streaming and RandomAccessFile so it will handle large files without loading everything into RAM.

Compatibility: Requires Java 8+ (but AES 256-bit may require JCE policy in older Java versions; modern OpenJDK includes unlimited strength).

Tamper and missing shards: If a shard is missing or corrupted, reconstruction will fail or produce incomplete output. For availability and fault tolerance, you can implement Reed-Solomon erasure coding so that only k of n shards are required to reconstruct. I can provide that implementation too if you want (requires a library or more code).

## 🛠️ Setup Instructions

### 1. Compile

```bash
javac SharderEncrypt.java SharderDecrypt.java
```
### 2. Encrypt
```bash
java SharderEncrypt <inputFilePath> <outputDirectory> <(INT)Shards> <password>
```
### 3. Decrypt and Reconstruct
```bash
java DecryptReconstruct   <your file.meta.properties>  <output new_file>
```
Enter the password and your file will be reconstructed.

Supported File Types

This method works for any binary or text file, because the program reads and writes in byte streams.

##✅ Supported examples:

.txt, .pdf, .docx

.jpg, .png, .mp4

.zip, .rar

Anything else (up to several GB, depending on your memory/disk)

❗Just make sure to have enough space in /Output and for final reassembly.
