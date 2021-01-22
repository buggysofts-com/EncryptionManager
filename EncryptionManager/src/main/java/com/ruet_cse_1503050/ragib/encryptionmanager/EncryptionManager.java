package com.ruet_cse_1503050.ragib.encryptionmanager;

import android.content.Context;
import android.util.Pair;

import androidx.documentfile.provider.DocumentFile;

import com.ruet_cse_1503050.ragib.encryptionmanager.utils.CommonUtils;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptionManager {

    public static int DATA_TYPE_ALL = 0;

    public static class Encryptor {

        private String key;
        private byte[] IV;
        private SecretKey secretKey;

        public Encryptor(String key) throws Exception {

            // store the key
            this.key = key;

            // Create Noonce
            this.IV = new byte[12 + (int) (System.currentTimeMillis() % 4L)];
            new SecureRandom().nextBytes(this.IV);

            // Prepare transformed secure key/password
            this.secretKey = generateSecretKey(key, this.IV);

        }

        public byte[] getEncryptedDataFromData(byte[] sourceData, int data_type, boolean embed_metadata) {

            byte[] return_data = null;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                // get encrypted content
                byte[] encrypted_data = cipher.doFinal(sourceData);

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    return_data = ByteBuffer.allocate(4 + 4 + this.IV.length + encrypted_data.length)
                            .putInt(data_type)
                            .putInt(this.IV.length)
                            .put(this.IV)
                            .put(encrypted_data)
                            .array();
                } else {
                    // store without any metadata
                    return_data = ByteBuffer.allocate(encrypted_data.length)
                            .put(encrypted_data)
                            .array();
                }


            } catch (Exception e) {
                e.printStackTrace();
            }

            return return_data;

        }

        public byte[] getEncryptedDataFromStream(InputStream stream, int data_type, boolean embed_metadata) {

            byte[] return_data = null;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                // get encrypted content
                byte[] encrypted_data = cipher.doFinal(CommonUtils.ReadStream(stream, true));

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    return_data = ByteBuffer.allocate(4 + 4 + this.IV.length + encrypted_data.length)
                            .putInt(data_type)
                            .putInt(this.IV.length)
                            .put(this.IV)
                            .put(encrypted_data)
                            .array();
                } else {
                    // store without any metadata
                    return_data = ByteBuffer.allocate(encrypted_data.length)
                            .put(encrypted_data)
                            .array();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return return_data;

        }

        public byte[] getEncryptedDataFromFile(File sourceFile, int data_type, boolean embed_metadata) {

            byte[] return_data = null;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                // get encrypted content
                byte[] encrypted_data = cipher.doFinal(CommonUtils.ReadFile(sourceFile));

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    return_data = ByteBuffer.allocate(4 + 4 + this.IV.length + encrypted_data.length)
                            .putInt(data_type)
                            .putInt(this.IV.length)
                            .put(this.IV)
                            .put(encrypted_data)
                            .array();
                } else {
                    // store without any metadata
                    return_data = ByteBuffer.allocate(encrypted_data.length)
                            .put(encrypted_data)
                            .array();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return return_data;

        }

        public boolean storeEncryptedFile(byte[] sourceData, File destFile, int data_type, boolean embed_metadata) {

            boolean success = true;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(destFile));

                // get encrypted content
                byte[] encrypted_data = cipher.doFinal(sourceData);

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    bos.write(
                            ByteBuffer.allocate(4 + 4 + this.IV.length + encrypted_data.length)
                                    .putInt(data_type)
                                    .putInt(this.IV.length)
                                    .put(this.IV)
                                    .put(encrypted_data)
                                    .array()
                    );
                } else {
                    // store without any metadata
                    bos.write(
                            ByteBuffer.allocate(encrypted_data.length)
                                    .put(encrypted_data)
                                    .array()
                    );
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeEncryptedFile(Context context, byte[] sourceData, DocumentFile destFile, int data_type, boolean embed_metadata) {

            boolean success = true;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                BufferedOutputStream bos = new BufferedOutputStream(context.getContentResolver().openOutputStream(destFile.getUri()));

                // get encrypted data
                byte[] encrypted_data = cipher.doFinal(sourceData);

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    bos.write(
                            ByteBuffer.allocate(4 + 4 + this.IV.length + encrypted_data.length)
                                    .putInt(data_type)
                                    .putInt(this.IV.length)
                                    .put(this.IV)
                                    .put(encrypted_data)
                                    .array()
                    );
                } else {
                    // store without any metadata
                    bos.write(
                            ByteBuffer.allocate(encrypted_data.length)
                                    .put(encrypted_data)
                                    .array()
                    );
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeEncryptedFile(File sourceFile, File destFile, int data_type, boolean embed_metadata) {

            boolean success = true;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                BufferedInputStream bin = new BufferedInputStream(new FileInputStream(sourceFile));
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(destFile));

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    bos.write(
                            ByteBuffer.allocate(4 + 4 + this.IV.length)
                                    .putInt(data_type)
                                    .putInt(this.IV.length)
                                    .put(this.IV).array()
                    );
                }

                long fileSize = sourceFile.length();
                int readnum;
                byte[] data = new byte[Math.min((embed_metadata ? (((int) fileSize) - (4 + 4 + this.IV.length)) : ((int) fileSize)), 8192)];
                while ((readnum = bin.read(data)) > 0) {
                    byte[] encrypted_data = cipher.update(data, 0, readnum);
                    if (encrypted_data != null) {
                        bos.write(encrypted_data);
                    }
                }

                byte[] final_encrypted_part = cipher.doFinal();
                if (final_encrypted_part != null) {
                    bos.write(final_encrypted_part);
                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeEncryptedFile(Context context, DocumentFile sourceFile, DocumentFile destFile, int data_type, boolean embed_metadata) {

            boolean success = true;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                BufferedInputStream bin = new BufferedInputStream(context.getContentResolver().openInputStream(sourceFile.getUri()));
                BufferedOutputStream bos = new BufferedOutputStream(context.getContentResolver().openOutputStream(destFile.getUri()));

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    bos.write(
                            ByteBuffer.allocate(4 + 4 + this.IV.length)
                                    .putInt(data_type)
                                    .putInt(this.IV.length)
                                    .put(this.IV).array()
                    );
                }

                long fileSize = sourceFile.length();
                int readnum;
                byte[] data = new byte[Math.min((embed_metadata ? (((int) fileSize) - (4 + 4 + this.IV.length)) : ((int) fileSize)), 8192)];
                while ((readnum = bin.read(data)) > 0) {
                    byte[] encrypted_data = cipher.update(data, 0, readnum);
                    if (encrypted_data != null) {
                        bos.write(encrypted_data);
                    }
                }
                byte[] final_encrypted_part = cipher.doFinal();
                if (final_encrypted_part != null) {
                    bos.write(final_encrypted_part);
                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeEncryptedFile(Context context, File sourceFile, DocumentFile destFile, int data_type, boolean embed_metadata) {

            boolean success = true;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                BufferedInputStream bin = new BufferedInputStream(new FileInputStream(sourceFile));
                BufferedOutputStream bos = new BufferedOutputStream(context.getContentResolver().openOutputStream(destFile.getUri()));

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    bos.write(
                            ByteBuffer.allocate(4 + 4 + this.IV.length)
                                    .putInt(data_type)
                                    .putInt(this.IV.length)
                                    .put(this.IV).array()
                    );
                }

                long fileSize = sourceFile.length();
                int readnum;
                byte[] data = new byte[Math.min((embed_metadata ? (((int) fileSize) - (4 + 4 + this.IV.length)) : ((int) fileSize)), 8192)];
                while ((readnum = bin.read(data)) > 0) {
                    byte[] encrypted_data = cipher.update(data, 0, readnum);
                    if (encrypted_data != null) {
                        bos.write(encrypted_data);
                    }
                }
                byte[] final_encrypted_part = cipher.doFinal();
                if (final_encrypted_part != null) {
                    bos.write(final_encrypted_part);
                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeEncryptedFile(Context context, DocumentFile sourceFile, File destFile, int data_type, boolean embed_metadata) {

            boolean success = true;

            try {

                // Initialize Cipher
                Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                cipher.init(
                        Cipher.ENCRYPT_MODE,
                        this.secretKey,
                        new GCMParameterSpec(128, this.IV)
                );

                BufferedInputStream bin = new BufferedInputStream(context.getContentResolver().openInputStream(sourceFile.getUri()));
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(destFile));

                if (embed_metadata) {
                    // store encryption metadata at start of the file and actual data and end
                    bos.write(
                            ByteBuffer.allocate(4 + 4 + this.IV.length)
                                    .putInt(data_type)
                                    .putInt(this.IV.length)
                                    .put(this.IV).array()
                    );
                }

                long fileSize = sourceFile.length();
                int readnum;
                byte[] data = new byte[Math.min((embed_metadata ? (((int) fileSize) - (4 + 4 + this.IV.length)) : ((int) fileSize)), 8192)];
                while ((readnum = bin.read(data)) > 0) {
                    byte[] encrypted_data = cipher.update(data, 0, readnum);
                    if (encrypted_data != null) {
                        bos.write(encrypted_data);
                    }
                }
                byte[] final_encrypted_part = cipher.doFinal();
                if (final_encrypted_part != null) {
                    bos.write(final_encrypted_part);
                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public Cipher getInitializedCipherForEncryption() throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.ENCRYPT_MODE,
                    this.secretKey,
                    new GCMParameterSpec(128, this.IV)
            );
            return cipher;
        }

        public byte[] Update(Cipher cipher, byte[] data) {
            return cipher.update(data);
        }

        public byte[] Finish(Cipher cipher, byte[] data) {
            byte[] return_data = null;
            try {
                return_data = cipher.doFinal(data);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return return_data;
        }

        public byte[] Finish(Cipher cipher) {
            byte[] return_data = null;
            try {
                return_data = cipher.doFinal();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return return_data;
        }


        public byte[] getIV() {
            return this.IV;
        }

        public byte[] getEncryptedIV() {
            return getEncryptedDataFromData(this.IV, EncryptionManager.DATA_TYPE_ALL, false);
        }

        /**
         * Function to generate a 128 bit key from the given password and initialization_vector
         *
         * @param password
         * @param initialization_vector
         * @return Secret key
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeySpecException
         */
        private SecretKey generateSecretKey(String password, byte[] initialization_vector) throws Exception {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), initialization_vector, 65536, 128); // AES-128
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] key = secretKeyFactory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "AES");
        }

    }

    public static class Decryptor {

        private String key;
        private byte[] IV;
        private SecretKey secretKey;
        private GCMParameterSpec parameterSpec;

        public Decryptor(String key) {

            // store key for future use
            this.key = key;

        }

        public Decryptor(String key, byte[] initialization_vector) throws Exception {

            // store components for future use

            this.key = key;
            this.IV = initialization_vector;

            // calculate secret key
            secretKey = generateSecretKey(this.key, this.IV);

            // calculate parameter spec
            parameterSpec = new GCMParameterSpec(128, this.IV);

        }

        public byte[] getDecryptedDataFromData(byte[] sourceData, boolean has_embedded_metadata) {

            byte[] return_data = null;

            try {

                if (has_embedded_metadata) {

                    ByteBuffer buffer = ByteBuffer.wrap(sourceData);

                    // get file type
                    int file_type = buffer.getInt();

                    // get this.IV size
                    int iv_size = buffer.getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    buffer.get(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // fill remaining data into a byte array
                    byte[] encrypted_data = new byte[buffer.remaining()];
                    buffer.get(encrypted_data);

                    // now decrypt actual data
                    return_data = cipher.doFinal(encrypted_data);

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            parameterSpec
                    );

                    // now decrypt data
                    return_data = cipher.doFinal(sourceData);

                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return return_data;

        }

        public byte[] getDecryptedDataFromStream(InputStream stream, boolean has_embedded_metadata) {

            byte[] return_data = null;

            try {

                BufferedInputStream bin = new BufferedInputStream(stream);

                if (has_embedded_metadata) {

                    // get file type
                    byte[] type_data = new byte[4];
                    bin.read(type_data);
                    int file_type = ByteBuffer.wrap(type_data).getInt();

                    // get this.IV size
                    byte[] iv_size_data = new byte[4];
                    bin.read(iv_size_data);
                    int iv_size = ByteBuffer.wrap(iv_size_data).getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    bin.read(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // get remaining data
                    byte[] encrypted_data = CommonUtils.ReadStream(bin, true);

                    // now decrypt actual data
                    return_data = cipher.doFinal(encrypted_data);

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // get data
                    byte[] encrypted_data = CommonUtils.ReadStream(bin, true);

                    // now decrypt data
                    return_data = cipher.doFinal(encrypted_data);

                }


                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return return_data;

        }

        public byte[] getDecryptedDataFromFile(File sourceFile, boolean has_embedded_metadata) {

            byte[] return_data = null;

            try {

                BufferedInputStream bin = new BufferedInputStream(new FileInputStream(sourceFile));

                if (has_embedded_metadata) {

                    // get file type
                    byte[] type_data = new byte[4];
                    bin.read(type_data);
                    int file_type = ByteBuffer.wrap(type_data).getInt();

                    // get this.IV size
                    byte[] iv_size_data = new byte[4];
                    bin.read(iv_size_data);
                    int iv_size = ByteBuffer.wrap(iv_size_data).getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    bin.read(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // get remaining data
                    byte[] encrypted_data = CommonUtils.ReadStream(bin, true);

                    // now decrypt actual data
                    return_data = cipher.doFinal(encrypted_data);

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // get data
                    byte[] encrypted_data = CommonUtils.ReadStream(bin, true);

                    // now decrypt data
                    return_data = cipher.doFinal(encrypted_data);

                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return return_data;

        }

        public boolean storeDecryptedFile(File sourceFile, File destFile, boolean has_embedded_metadata) {

            boolean success = true;

            try {

                BufferedInputStream bin = new BufferedInputStream(new FileInputStream(sourceFile));
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(destFile));

                if (has_embedded_metadata) {

                    // get file type
                    byte[] type_data = new byte[4];
                    bin.read(type_data);
                    int file_type = ByteBuffer.wrap(type_data).getInt();

                    // get this.IV size
                    byte[] iv_size_data = new byte[4];
                    bin.read(iv_size_data);
                    int iv_size = ByteBuffer.wrap(iv_size_data).getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    bin.read(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min((((int) fileSize) - (4 + 4 + this.IV.length)), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min(((int) fileSize), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeDecryptedFile(byte[] sourceData, File destFile, boolean has_embedded_metadata) {

            boolean success = true;

            try {

                if (has_embedded_metadata) {

                    ByteBuffer buffer = ByteBuffer.wrap(sourceData);

                    // get file type
                    int file_type = buffer.getInt();

                    // get this.IV size
                    int iv_size = buffer.getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    buffer.get(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // fill remaining data into a byte array
                    byte[] encrypted_data = new byte[buffer.remaining()];
                    buffer.get(encrypted_data);

                    // now decrypt actual data
                    CommonUtils.WriteToFile(
                            destFile,
                            cipher.doFinal(encrypted_data)
                    );

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // now decrypt data
                    CommonUtils.WriteToFile(
                            destFile,
                            cipher.doFinal(sourceData)
                    );

                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeDecryptedFile(Context context, byte[] sourceData, DocumentFile destFile, boolean has_embedded_metadata) {

            boolean success = true;

            try {

                if (has_embedded_metadata) {

                    ByteBuffer buffer = ByteBuffer.wrap(sourceData);

                    // get file type
                    int file_type = buffer.getInt();

                    // get this.IV size
                    int iv_size = buffer.getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    buffer.get(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // fill remaining data into a byte array
                    byte[] encrypted_data = new byte[buffer.remaining()];
                    buffer.get(encrypted_data);

                    // now decrypt actual data
                    CommonUtils.WriteToFile(
                            context,
                            destFile,
                            cipher.doFinal(encrypted_data)
                    );

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    // now decrypt data
                    CommonUtils.WriteToFile(
                            context,
                            destFile,
                            cipher.doFinal(sourceData)
                    );

                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeDecryptedFile(Context context, File sourceFile, DocumentFile destFile, boolean has_embedded_metadata) {

            boolean success = true;

            try {

                BufferedInputStream bin = new BufferedInputStream(new FileInputStream(sourceFile));
                BufferedOutputStream bos = new BufferedOutputStream(context.getContentResolver().openOutputStream(destFile.getUri()));

                if (has_embedded_metadata) {

                    // get file type
                    byte[] type_data = new byte[4];
                    bin.read(type_data);
                    int file_type = ByteBuffer.wrap(type_data).getInt();

                    // get this.IV size
                    byte[] iv_size_data = new byte[4];
                    bin.read(iv_size_data);
                    int iv_size = ByteBuffer.wrap(iv_size_data).getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    bin.read(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min((((int) fileSize) - (4 + 4 + this.IV.length)), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min(((int) fileSize), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeDecryptedFile(Context context, DocumentFile sourceFile, File destFile, boolean has_embedded_metadata) {

            boolean success = true;

            try {

                BufferedInputStream bin = new BufferedInputStream(context.getContentResolver().openInputStream(sourceFile.getUri()));
                BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(destFile));

                if (has_embedded_metadata) {

                    // get file type
                    byte[] type_data = new byte[4];
                    bin.read(type_data);
                    int file_type = ByteBuffer.wrap(type_data).getInt();

                    // get this.IV size
                    byte[] iv_size_data = new byte[4];
                    bin.read(iv_size_data);
                    int iv_size = ByteBuffer.wrap(iv_size_data).getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    bin.read(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min((((int) fileSize) - (4 + 4 + this.IV.length)), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min(((int) fileSize), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public boolean storeDecryptedFile(Context context, DocumentFile sourceFile, DocumentFile destFile, boolean has_embedded_metadata) {

            boolean success = true;

            try {

                BufferedInputStream bin = new BufferedInputStream(context.getContentResolver().openInputStream(sourceFile.getUri()));
                BufferedOutputStream bos = new BufferedOutputStream(context.getContentResolver().openOutputStream(destFile.getUri()));

                if (has_embedded_metadata) {

                    // get file type
                    byte[] type_data = new byte[4];
                    bin.read(type_data);
                    int file_type = ByteBuffer.wrap(type_data).getInt();

                    // get this.IV size
                    byte[] iv_size_data = new byte[4];
                    bin.read(iv_size_data);
                    int iv_size = ByteBuffer.wrap(iv_size_data).getInt();

                    // get actual IV
                    this.IV = new byte[iv_size];
                    bin.read(this.IV);

                    // Prepare your key/password
                    this.secretKey = generateSecretKey(this.key, this.IV);

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min((((int) fileSize) - (4 + 4 + this.IV.length)), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                } else {

                    // Initialize Cipher
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                    cipher.init(
                            Cipher.DECRYPT_MODE,
                            this.secretKey,
                            new GCMParameterSpec(128, this.IV)
                    );

                    long fileSize = sourceFile.length();
                    int readnum;
                    byte[] data = new byte[Math.min(((int) fileSize), 8192)];
                    while ((readnum = bin.read(data)) > 0) {
                        byte[] decrypted_data = cipher.update(data, 0, readnum);
                        if (decrypted_data != null) {
                            bos.write(decrypted_data);
                        }
                    }
                    byte[] final_decrypted_part = cipher.doFinal();
                    if (final_decrypted_part != null) {
                        bos.write(final_decrypted_part);
                    }

                }

                try {
                    bin.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

                try {
                    bos.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }

            } catch (Exception e) {
                e.printStackTrace();
                success = false;
            }

            return success;

        }

        public Cipher getInitializedCipherForDecryption() throws Exception {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(
                    Cipher.DECRYPT_MODE,
                    this.secretKey,
                    new GCMParameterSpec(128, this.IV)
            );
            return cipher;
        }

        public byte[] Update(Cipher cipher, byte[] data) {
            return cipher.update(data);
        }

        public byte[] Finish(Cipher cipher, byte[] data) {
            byte[] return_data = null;
            try {
                return_data = cipher.doFinal(data);
            } catch (Exception e) {
                e.printStackTrace();
            }
            return return_data;
        }

        public byte[] Finish(Cipher cipher) {
            byte[] return_data = null;
            try {
                return_data = cipher.doFinal();
            } catch (Exception e) {
                e.printStackTrace();
            }
            return return_data;
        }

        public byte[] getIV() {
            return this.IV;
        }

        /**
         * Function to generate a 128 bit key from the given password and initialization_vector
         *
         * @param password
         * @param initialization_vector
         * @return Secret key
         * @throws NoSuchAlgorithmException
         * @throws InvalidKeySpecException
         */
        private SecretKey generateSecretKey(String password, byte[] initialization_vector) throws Exception {
            KeySpec spec = new PBEKeySpec(password.toCharArray(), initialization_vector, 65536, 128); // AES-128
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            byte[] key = secretKeyFactory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, "AES");
        }

        public Pair<Integer, byte[]> getDecryptionMetadata(byte[] metadata) throws Exception {

            ByteBuffer buffer = ByteBuffer.wrap(metadata);

            // get file type
            int file_type = buffer.getInt();

            // get this.IV size
            int iv_size = buffer.getInt();

            // get actual IV
            byte[] init_vector_part = new byte[iv_size];
            buffer.get(init_vector_part);

            byte[] encrypted_part = new byte[buffer.remaining()];

            byte[] decrypted_part = getDecryptedDataFromData(encrypted_part, false);

            return (decrypted_part != null) ? new Pair<>(file_type, init_vector_part) : null;

        }

    }

}
