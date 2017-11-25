/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.evgeniy_mh.simpleaescipher.AESEngine;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;

/**
 *
 * @author evgeniy
 */
public class ECBCEncryptor {

    private AES mAES;
    
    public ECBCEncryptor(){
        mAES=new AES();
    }

    public void getECBC(File in, File out, byte[] key) throws IOException {

        byte[] tempKey = key;
        if (key.length % AES.BLOCK_SIZE != 0) {
            tempKey = AES_CTREncryptor.PKCS7(key);
        }
        mAES.makeKey(tempKey, 128, AES.DIR_BOTH);

        RandomAccessFile INraf = new RandomAccessFile(in, "r");
        int nBlocks = CommonTools.countBlocks(in, AES.BLOCK_SIZE); //сколько блоков открытого текста

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

        Files.write(out.toPath(), IV, StandardOpenOption.WRITE);

    }

}
