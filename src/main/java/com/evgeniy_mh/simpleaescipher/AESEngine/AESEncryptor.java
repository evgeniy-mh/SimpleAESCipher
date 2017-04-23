package com.evgeniy_mh.simpleaescipher.AESEngine;

import com.evgeniy_mh.simpleaescipher.MainController;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Created by evgeniy on 08.04.17.
 */
public class AESEncryptor {

    private AES mAES;

    public AESEncryptor() {
        mAES = new AES();
    }

    /*public byte[] encrypt(byte[] message, byte[] key) {

        byte[] nonce = ByteBuffer.allocate(8).putInt(getNonce()).array();
        byte[] counter = ByteBuffer.allocate(8).putInt(0).array();
        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE]; //используется в раундах
        byte[] nonceAndCounterInfo = new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter
        System.arraycopy(nonce, 0, nonceAndCounterInfo, 0, 4);
        System.arraycopy(counter, 0, nonceAndCounterInfo, 4, 4);

        int n = 0; //сколько байт будет добавлено   

        if (message.length % AES.BLOCK_SIZE != 0) {
            n = countDeltaBlocks(message); //сколько байт будет добавлено
            message = PKCS7(message);
        }
        if (key.length % AES.BLOCK_SIZE != 0) {
            key = PKCS7(key);
        }
        mAES.makeKey(key, 128, AES.DIR_BOTH);

        byte[] res;
        if (n == 0) {
            res = new byte[8 + message.length + 16]; //если сообщение было кратно размеру блока то в конце добавляется блок байтов со значением 16
        } else {
            res = new byte[8 + message.length];
        }

        int nBlocks = countBlocks(message); //сколько блоков открытого текста
        if (n == 0) {
            nBlocks++;
        }

        byte[] temp;
        for (int i = 0; i < nBlocks; i++) {

            if (n == 0 && (i + 1) == nBlocks) { //если сообщение было кратно размеру блока то в конце добавляется блок байтов со значением 16
                temp = new byte[16];
                for (int j = 0; j < 16; j++) {
                    temp[j] = 16;
                }
            } else {
                temp = Arrays.copyOfRange(message, i * 16, (i + 1) * 16); //p_i            
            }
            counter = ByteBuffer.allocate(8).putInt(i).array();
            System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
            System.arraycopy(counter, 0, nonceAndCounter, 12, 4);//nonceAndCounter: 0000nnnn|0000cccc

            byte[] k = new byte[AES.BLOCK_SIZE]; // k_i
            mAES.encrypt(nonceAndCounter, k);

            byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
            for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor p_i и k_i
                c[j] = (byte) (temp[j] ^ k[j]);
            }
            for (int j = i * 16 + 8, m = 0; j < (i + 1) * 16 + 8; j++, m++) { //копирование бит блока в рез. массив
                res[j] = c[m];
            }
        }
        System.arraycopy(nonceAndCounterInfo, 0, res, 0, 8); //добавление 8 байт которые в начало сообщения которые несут инфу о nonce и counter
        return res;
    }*/
    
    public void encrypt(File in,File out, byte[] key){
        
        byte[] nonce = ByteBuffer.allocate(8).putInt(getNonce()).array();
        byte[] counter = ByteBuffer.allocate(8).putInt(0).array();
        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE]; //используется в раундах //nonceAndCounter: 0000nnnn|0000cccc
        byte[] nonceAndCounterInfo = new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter //nonceAndCounterInfo: nnnncccc
        System.arraycopy(nonce, 0, nonceAndCounterInfo, 0, 4);
        System.arraycopy(counter, 0, nonceAndCounterInfo, 4, 4);
        
        int n = 0; //сколько байт будет добавлено   

        //ebugPrintByteArray("before pkcs", readBytesFromFile(in));        
        //n = countDeltaBlocks(in); //сколько байт будет добавлено
        PKCS(in);  
        //System.out.println("n="+n);
        //debugPrintByteArray("after pkcs", readBytesFromFile(in));
        if (key.length % AES.BLOCK_SIZE != 0) {
            key = PKCS7(key);
        }
        mAES.makeKey(key, 128, AES.DIR_BOTH);
        
        
        
        
        
    }

    public byte[] decrypt(byte[] message, byte[] key) {
        byte[] nonce = new byte[8];
        System.arraycopy(message, 0, nonce, 0, 4);
        byte[] counter = new byte[8];
        System.arraycopy(message, 4, counter, 0, 4);

        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE];

        if (key.length % AES.BLOCK_SIZE != 0) {
            key = PKCS7(key);
        }
        mAES.makeKey(key, 128, AES.DIR_BOTH);

        byte[] resAllBlocks = new byte[message.length - 8];
        int n = countBlocks(message); //сколько блоков шифро текста

        byte[] temp;
        for (int i = 0; i < n; i++) {

            temp = Arrays.copyOfRange(message, i * 16 + 8, (i + 1) * 16 + 8); //p_i
            counter = ByteBuffer.allocate(8).putInt(i).array();
            System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
            System.arraycopy(counter, 0, nonceAndCounter, 12, 4);

            byte[] k = new byte[AES.BLOCK_SIZE]; // k_i

            mAES.encrypt(nonceAndCounter, k);

            byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
            for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor p_i и k_i
                c[j] = (byte) (temp[j] ^ k[j]);
            }
            for (int j = i * 16, m = 0; j < (i + 1) * 16; j++, m++) { //копирование бит блока в рез. массив
                resAllBlocks[j] = c[m];
            }
        }

        int nToDeleteBytes = resAllBlocks[resAllBlocks.length - 1]; 
        if(nToDeleteBytes<=0 || nToDeleteBytes>16) nToDeleteBytes=0; //на случай дешифрования с неправильным ключем
        
        byte[] res = Arrays.copyOfRange(resAllBlocks, 0, resAllBlocks.length - nToDeleteBytes);
        return res;
    }

    private byte[] PKCS7(byte[] b) {
        int n = countDeltaBlocks(b); //сколько байт нужно добавить и какое у них будет значение 
        if (n != 0) {
            byte[] bPadded = new byte[b.length + n];
            for (int i = 0; i < bPadded.length; i++) {
                if (i < b.length) {
                    bPadded[i] = b[i];
                } else {
                    bPadded[i] = (byte) n;
                }
            }
            return bPadded;
        } else {
            return b;
        }
    }
    
    private void PKCS(File f){        
            int n = countDeltaBlocks(f); //сколько байт нужно добавить и какое у них будет значение
            if(n==0) n=16;
            
                try {
                    byte[] appendBytes=new byte[n];
                    for(int i=0;i<n;i++) appendBytes[i]=(byte)n;
                    appendToFile(f, appendBytes);
                } catch (IOException ex) {
                    Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
                }
            
    }
    
    private void appendToFile(File f,byte[] b) throws FileNotFoundException, IOException{
        RandomAccessFile raf=new RandomAccessFile(f,"rw");
        //System.out.println("file pointer="+raf.getFilePointer());
        raf.seek(raf.length());
        raf.setLength(raf.length()+b.length);
        raf.write(b);        
        //System.out.println("file pointer="+raf.getFilePointer());        
        raf.close();
    }

    int getNonce() {
        return Nonce.getInstance().getNonce();
    }

    static public void debugPrintByteArray(String mes, byte[] array) {
        System.out.println(mes);
        for (int i = 0; i < array.length; i++) {
            System.out.print(String.format("0x%08X", array[i]) + " ");
        }
        System.out.println();
    }

    private int countDeltaBlocks(byte[] b) { //подсчет скольких байт не хватает до полного блока
        return AES.BLOCK_SIZE - b.length % AES.BLOCK_SIZE;
    }
    
    private int countDeltaBlocks(File f) { //подсчет скольких байт не хватает в файле до полного блока
        return (int) (AES.BLOCK_SIZE - f.length() % AES.BLOCK_SIZE);
    }

    public int countBlocks(byte[] b) { //подсчет целых блоков
        return b.length / AES.BLOCK_SIZE;
    }
    
    private byte[] readBytesFromFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

}
