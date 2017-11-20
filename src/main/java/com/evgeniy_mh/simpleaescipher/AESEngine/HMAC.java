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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author evgeniy
 */
public class HMAC {

    private static final int BLOCK_SIZE = 64;

    private static byte[] ipad;
    private static byte[] opad;

    private MessageDigest md5;

    public HMAC() {
        ipad = new byte[BLOCK_SIZE];
        opad = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ipad[i] = Byte.decode("0x36");
            opad[i] = Byte.decode("0x5c");
        }

        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(HMAC.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void getHMAC(File in, File out, byte[] key) throws IOException {
        key = prepareKey(key);

        byte[] ki = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ki[i] = (byte) (key[i] ^ ipad[i]);
        }

        byte[] ko = new byte[BLOCK_SIZE];
        for (int i = 0; i < BLOCK_SIZE; i++) {
            ko[i] = (byte) (key[i] ^ opad[i]);
        }

        byte[] m = Files.readAllBytes(in.toPath());
        byte[] temp = concat(ki, m);
        temp = md5.digest(temp);
        
        temp=concat(ko, temp);
        temp=md5.digest(temp);
        
        Files.write(out.toPath(), temp, StandardOpenOption.WRITE);
    }

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

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);

        return result;
    }

}
