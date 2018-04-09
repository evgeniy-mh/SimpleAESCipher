package com.evgeniy_mh.simpleaescipher.AESEngine;

import com.evgeniy_mh.simpleaescipher.CommonUtils;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import javafx.concurrent.Task;

public class ECBCEncryptor {

    private AES mAES;

    public ECBCEncryptor() {
        mAES = new AES();
    }

    /**
     * Создает Task для подсчета ECBC
     *
     * @param in Файл шифрованного текста
     * @param out Файл для сохранения результата
     * @param key1 Ключ шифрования
     * @param key2 Доп. ключ ECBC
     * @param appendToInFile Если true то ECBC будет добавлен в конец файла in,
     */
    public Task getECBC(File in, File out, byte[] key1, byte[] key2, boolean appendToInFile) {
        return new Task<Void>() {
            @Override
            protected Void call() {
                //try {
                    /*byte[] tempKey1 = key1;
                    if (key1.length % AES.BLOCK_SIZE != 0) {
                        tempKey1 = AES_CTREncryptor.PKCS7(key1);
                    }

                    byte[] tempKey2 = key2;
                    if (key2.length % AES.BLOCK_SIZE != 0) {
                        tempKey2 = AES_CTREncryptor.PKCS7(key2);
                    }

                    mAES.makeKey(tempKey1, 128, AES.DIR_BOTH);

                    RandomAccessFile INraf = new RandomAccessFile(in, "r");
                    int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE); //сколько блоков открытого текста

                    byte[] temp = new byte[AES.BLOCK_SIZE];
                    byte[] IV = new byte[AES.BLOCK_SIZE];
                    java.util.Arrays.fill(IV, (byte) 0);

                    for (int i = 0; i < nBlocks + 1; i++) {
                        INraf.seek(i * 16); //установка указателя для считывания файла

                        if ((i + 1) == nBlocks + 1) { //последняя итерация
                            int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
                            if (deltaToBlock > 0) {
                                temp = new byte[deltaToBlock];
                                INraf.read(temp, 0, deltaToBlock);  //считывание неполного блока в temp
                                temp = AES_CTREncryptor.PKCS7(temp);
                            } else {
                                temp = new byte[AES.BLOCK_SIZE];
                                for (int t = 0; t < AES.BLOCK_SIZE; t++) {
                                    temp[t] = (byte) AES.BLOCK_SIZE;
                                }
                            }
                        } else {
                            INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp
                        }

                        for (int k = 0; k < AES.BLOCK_SIZE; k++) {
                            temp[k] = (byte) (temp[k] ^ IV[k]);
                        }
                        mAES.encrypt(temp, IV);
                    }
                    mAES.makeKey(tempKey2, 128, AES.DIR_BOTH);
                    mAES.encrypt(IV, IV);*/
                    
                    Task<MACResult> ECBCTask = getECBC(in, key1, key2);
                    ECBCTask.setOnSucceeded(value -> {
                        try {
                            byte[] res=ECBCTask.getValue().getMAC();
                            
                            if (appendToInFile) {
                                Files.write(in.toPath(), ECBCTask.getValue().getMAC(), StandardOpenOption.APPEND);
                            } else {                                
                                Files.write(out.toPath(), ECBCTask.getValue().getMAC(), StandardOpenOption.WRITE);
                            }
                        } catch (IOException ex) {
                            CommonUtils.reportExceptionToMainThread(ex, "Exception in encrypt thread, ECBC task!");
                        }
                    });
                    ECBCTask.run();
                    return null;
                }
            }
        ;
    }

    public Task<MACResult> getECBC(File in, byte[] key1, byte[] key2) {
        return new Task<MACResult>() {
            @Override
            protected MACResult call() {
                try {
                    byte[] tempKey1 = key1;
                    if (key1.length % AES.BLOCK_SIZE != 0) {
                        tempKey1 = AES_CTREncryptor.PKCS7(key1);
                    }

                    byte[] tempKey2 = key2;
                    if (key2.length % AES.BLOCK_SIZE != 0) {
                        tempKey2 = AES_CTREncryptor.PKCS7(key2);
                    }

                    mAES.makeKey(tempKey1, 128, AES.DIR_BOTH);

                    RandomAccessFile INraf = new RandomAccessFile(in, "r");
                    int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE); //сколько блоков открытого текста

                    byte[] temp = new byte[AES.BLOCK_SIZE];
                    byte[] IV = new byte[AES.BLOCK_SIZE];
                    java.util.Arrays.fill(IV, (byte) 0);

                    for (int i = 0; i < nBlocks + 1; i++) {
                        INraf.seek(i * 16); //установка указателя для считывания файла

                        if ((i + 1) == nBlocks + 1) { //последняя итерация
                            int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
                            if (deltaToBlock > 0) {
                                temp = new byte[deltaToBlock];
                                INraf.read(temp, 0, deltaToBlock);  //считывание неполного блока в temp
                                temp = AES_CTREncryptor.PKCS7(temp);
                            } else {
                                temp = new byte[AES.BLOCK_SIZE];
                                for (int t = 0; t < AES.BLOCK_SIZE; t++) {
                                    temp[t] = (byte) AES.BLOCK_SIZE;
                                }
                            }
                        } else {
                            INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp
                        }

                        for (int k = 0; k < AES.BLOCK_SIZE; k++) {
                            temp[k] = (byte) (temp[k] ^ IV[k]);
                        }
                        mAES.encrypt(temp, IV);
                    }
                    mAES.makeKey(tempKey2, 128, AES.DIR_BOTH);
                    mAES.encrypt(IV, IV);

                    return new MACResult(IV);
                } catch (IOException ex) {
                    CommonUtils.reportExceptionToMainThread(ex, "Exception in encrypt thread, ECBC task!");
                }
                return null;
            }
        };
    }
}
