package com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javafx.concurrent.Task;

/**
 *
 * @author evgeniy
 */
public class HMACEncryptor {

    private static final int BLOCK_SIZE = 64;
    private static byte[] ipad;
    private static byte[] opad;
    private MessageDigest md5;

    public HMACEncryptor() {
        ipad = new byte[BLOCK_SIZE];
        opad = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ipad[i] = Byte.decode("0x36");
            opad[i] = Byte.decode("0x5c");
        }

        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            CommonTools.reportExceptionToMainThread(ex,"Exception in HMACEncryptor() !");
        }
    }

    /**
     * Создает Task для подсчета HMAC
     * @param in Файл шифрованного текста
     * @param out Файл для сохранения результата
     * @param key Ключ шифрования
     */
    public Task getHMAC(File in, File out, byte[] key) {
        return new Task<Void>() {
            @Override
            protected Void call() {
                try {       
                    byte[] tempkey = prepareKey(key);

                    byte[] Si = new byte[BLOCK_SIZE];
                    for (int i = 0; i < BLOCK_SIZE; i++) {
                        Si[i] = (byte) (tempkey[i] ^ ipad[i]);
                    }

                    byte[] So = new byte[BLOCK_SIZE];
                    for (int i = 0; i < BLOCK_SIZE; i++) {
                        So[i] = (byte) (tempkey[i] ^ opad[i]);
                    }

                    byte[] m = Files.readAllBytes(in.toPath());
                    byte[] temp = CommonTools.concat(Si, m);
                    temp = md5.digest(temp);

                    temp = CommonTools.concat(So, temp);
                    temp = md5.digest(temp);

                    Files.write(out.toPath(), temp, StandardOpenOption.WRITE);
                } catch (IOException ex) {
                    CommonTools.reportExceptionToMainThread(ex,"Exception in encrypt thread, HMAC task!");
                }
                return null;
            }
        };
    }
    
    /**
     * Подготовка ключа по алгоритму HMAC
     * @param key Ключ шифрования
     * @return Подготовленный ключ шифрования
     */
    private byte[] prepareKey(byte[] key) {
        byte[] resultKey = new byte[BLOCK_SIZE];

        if (key.length == BLOCK_SIZE) {
            resultKey = key;
        } else if (key.length > BLOCK_SIZE) {
            byte[] temp = md5.digest(key);
            System.arraycopy(temp, 0, resultKey, 0, temp.length);

            for (int i = temp.length; i < BLOCK_SIZE; i++) {
                resultKey[i] = 0;
            }
        } else { //if(key.length < BLOCK_SIZE)
            System.arraycopy(key, 0, resultKey, 0, key.length);
            for (int i = key.length; i < BLOCK_SIZE; i++) {
                resultKey[i] = 0;
            }
        }
        return resultKey;
    }
}
