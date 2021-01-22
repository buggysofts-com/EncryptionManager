package com.ruet_cse_1503050.ragib.encryptionmanager.utils;

import android.content.Context;

import androidx.documentfile.provider.DocumentFile;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;

public final class CommonUtils {

    public static byte[] ReadStream(InputStream stream, boolean close_stream) {

        byte[] return_data = null;

        BufferedInputStream bin = null;
        ByteArrayOutputStream bout = null;

        try {

            bin = new BufferedInputStream(stream);
            bout = new ByteArrayOutputStream();

            int readNum;
            byte[] data = new byte[8192];
            while ((readNum = bin.read(data)) >= 0) {
                bout.write(data, 0, readNum);
            }

            return_data = bout.toByteArray();

        } catch (Exception e) {
            e.printStackTrace();
        }

        try {
            if (bout != null) {
                bout.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        if (close_stream) {
            try {
                if (bin != null) {
                    bin.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }

        return return_data;

    }

    public static byte[] ReadFile(File file) {

        byte[] ret;

        if (file != null && file.exists()) {

            ByteArrayOutputStream byte_out = new ByteArrayOutputStream();
            BufferedInputStream buff_in = null;
            try {

                buff_in = new BufferedInputStream(new FileInputStream(file));

                int readnum;
                byte[] data = new byte[8192];
                while ((readnum = buff_in.read(data)) >= 0) {
                    byte_out.write(data, 0, readnum);
                }

                ret = byte_out.toByteArray();

            } catch (Exception e) {
                e.printStackTrace();
                ret = "".getBytes();
            }
            try {
                if (buff_in != null) {
                    buff_in.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            return (ret);

        } else {
            return "".getBytes();
        }
    }

    public static byte[] ReadFile(File file, int readLen) {
        if (file != null && file.exists()) {
            byte[] ret = new byte[readLen];
            DataInputStream din = null;
            try {
                din = new DataInputStream(new FileInputStream(file));
                din.readFully(ret, 0, ret.length);
            } catch (Exception e) {
                e.printStackTrace();
                ret = "".getBytes();
            }
            try {
                if (din != null) {
                    din.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return (ret);
        } else {
            return "".getBytes();
        }
    }

    public static byte[] ReadFile(Context context, DocumentFile file, int readLen) {
        if (file != null && file.exists()) {
            byte[] ret = new byte[readLen];
            DataInputStream din = null;
            try {
                din = new DataInputStream(context.getContentResolver().openInputStream(file.getUri()));
                din.readFully(ret, 0, ret.length);
            } catch (Exception e) {
                e.printStackTrace();
                ret = "".getBytes();
            }
            try {
                if (din != null) {
                    din.close();
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
            return (ret);
        } else {
            return "".getBytes();
        }
    }

    public static void WriteToFile(File file, byte[] data) {
        BufferedOutputStream buff_out = null;
        try {
            buff_out = new BufferedOutputStream(new FileOutputStream(file));
            buff_out.write(data, 0, data.length);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            if (buff_out != null) {
                buff_out.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void WriteToFile(Context context, DocumentFile file, byte[] data) {
        BufferedOutputStream os = null;
        try {
            os = new BufferedOutputStream(
                    context.getContentResolver().openOutputStream(
                            file.getUri()
                    )
            );
            os.write(data, 0, data.length);
        } catch (Exception e) {
            e.printStackTrace();
        }
        try {
            if (os != null) {
                os.close();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
