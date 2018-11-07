package com.evgeniy_mh.simpleaescipher.AESEngine;

import com.evgeniy_mh.simpleaescipher.CommonUtils;
import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.util.Random;
import javafx.concurrent.Task;
import javafx.scene.control.ProgressIndicator;

public class AES_CBCEncryptor extends Encryptor {

    public AES_CBCEncryptor(ProgressIndicator progressIndicator) {
        super(progressIndicator);
    }

    @Override
    public Task encrypt(File in, File out, byte[] key) {
        return new Task<Void>() {
            @Override
            protected Void call() throws IOException {
                Random random = new Random();
                byte[] IV = new byte[AES.BLOCK_SIZE];
                random.nextBytes(IV);

                byte[] tempKey = key;
                if (key.length % AES.BLOCK_SIZE != 0) {
                    tempKey = PKCS7.PKCS7(key);
                }
                mAES.makeKey(tempKey, 128, AES.DIR_BOTH);

                try {
                    RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
                    OUTraf.setLength(8 + in.length());
                    OUTraf.write(IV);

                    RandomAccessFile INraf = new RandomAccessFile(in, "r");

                    int nBlocks = CommonUtils.countBlocks(in, AES.BLOCK_SIZE); //сколько блоков открытого текста
                    byte[] temp = new byte[AES.BLOCK_SIZE]; //считываемый блок исходного текста
                    byte[] prev = new byte[AES.BLOCK_SIZE]; //предыдущий зашифрованный блок

                    for (int i = 0; i < nBlocks + 1; i++) {
                        INraf.seek(i * 16); //установка указателя для считывания файла

                        if ((i + 1) == nBlocks + 1) { //последняя итерация
                            int deltaToBlock = (int) (in.length() % AES.BLOCK_SIZE);
                            if (deltaToBlock > 0) {
                                temp = new byte[deltaToBlock];
                                INraf.read(temp, 0, deltaToBlock);  //считывание неполного блока в temp
                                temp = PKCS7.PKCS7(temp);
                            } else {
                                temp = new byte[AES.BLOCK_SIZE];
                                for (int t = 0; t < AES.BLOCK_SIZE; t++) {
                                    temp[t] = (byte) AES.BLOCK_SIZE;
                                }
                            }
                        } else {
                            INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp
                        }

                        byte[] k = new byte[AES.BLOCK_SIZE];
                        if (i == 0) { //первая итерация
                            for (int j = 0; j < AES.BLOCK_SIZE; j++) {
                                k[j] = (byte) (IV[j] ^ temp[j]);
                            }
                        } else {
                            for (int j = 0; j < AES.BLOCK_SIZE; j++) {
                                k[j] = (byte) (prev[j] ^ temp[j]);
                            }
                        }

                        mAES.encrypt(k, prev);
                        OUTraf.write(k);
                        progressIndicator.setProgress((double) i / nBlocks);
                    }
                    INraf.close();
                    OUTraf.close();
                } catch (IOException e) {
                    CommonUtils.reportExceptionToMainThread(e, "Exception in encrypt thread!");
                }
                progressIndicator.setProgress(0.0);
                return null;
            }
        };
    }

    @Override

    public Task decrypt(File in, File out, byte[] key) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
