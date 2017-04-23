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
    
    public void encrypt(File in, File out, byte[] key) {

        byte[] nonce = ByteBuffer.allocate(8).putInt(getNonce()).array();
        byte[] counter = ByteBuffer.allocate(8).putInt(0).array();
        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE]; //используется в раундах //nonceAndCounter: 0000nnnn|0000cccc
        byte[] nonceAndCounterInfo = new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter //nonceAndCounterInfo: nnnncccc
        System.arraycopy(nonce, 0, nonceAndCounterInfo, 0, 4);
        System.arraycopy(counter, 0, nonceAndCounterInfo, 4, 4);

        //int n = 0; //сколько байт будет добавлено

        //debugPrintByteArray("before pkcs", readBytesFromFile(in));
        //n = countDeltaBlocks(in); //сколько байт будет добавлено
        PKCS(in);
        //System.out.println("n="+n);
        //debugPrintByteArray("after pkcs", readBytesFromFile(in));
        if (key.length % AES.BLOCK_SIZE != 0) {
            key = PKCS7(key);
        }
        mAES.makeKey(key, 128, AES.DIR_BOTH);

        try {
            RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
            OUTraf.setLength(8+in.length());
            OUTraf.write(nonceAndCounterInfo);
            
            //System.out.println("OUTraf.getFilePointer()="+OUTraf.getFilePointer());
            //debugPrintByteArray("OUTraf", readBytesFromFile(out));
            
            RandomAccessFile INraf = new RandomAccessFile(in, "r");
            
            int nBlocks = countBlocks(in); //сколько блоков открытого текста
            byte[] temp=new byte[AES.BLOCK_SIZE];
            for (int i = 0; i < nBlocks; i++) {             
                INraf.seek(i * 16); //утсновка указателя для считывания файла
                INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp

                //System.out.println("block "+i);
                //debugPrintByteArray("temp=", temp);
                counter = ByteBuffer.allocate(8).putInt(i).array();
                System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
                System.arraycopy(counter, 0, nonceAndCounter, 12, 4);//nonceAndCounter: 0000nnnn|0000cccc

                byte[] k = new byte[AES.BLOCK_SIZE]; // k_i
                mAES.encrypt(nonceAndCounter, k);

                byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
                for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor p_i и k_i
                    c[j] = (byte) (temp[j] ^ k[j]);
                }
                OUTraf.write(c);
                
            }
            //debugPrintByteArray("OUTraf", readBytesFromFile(out));
            OUTraf.close();
            INraf.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    public void decrypt(File in, File out, byte[] key) {
        byte[] nonceAndCounterInfo = new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter //nonceAndCounterInfo: nnnncccc
        try {
            nonceAndCounterInfo=readBytesFromFile(in, 0, 8);
        } catch (IOException ex) {
            Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] nonce = new byte[8];
        byte[] counter = new byte[8];
        System.arraycopy(nonceAndCounterInfo, 0, nonce, 0, 4);
        System.arraycopy(nonceAndCounterInfo, 4, counter, 0, 4);
        
        //debugPrintByteArray("nonce=", nonce);
        //debugPrintByteArray("counter=", counter);

        byte[] nonceAndCounter = new byte[AES.BLOCK_SIZE];

        if (key.length % AES.BLOCK_SIZE != 0) {
            key = PKCS7(key);
        }
        mAES.makeKey(key, 128, AES.DIR_BOTH);    
        try {
            RandomAccessFile OUTraf = new RandomAccessFile(out, "rw");
            OUTraf.setLength(in.length()-8);
            RandomAccessFile INraf = new RandomAccessFile(in, "r");
            
            int nBlocks = countBlocks(in); //сколько блоков шифро текста
            int nToDeleteBytes=0; //сколько байт нужно удалить с конца сообщения
            
            byte[] temp=new byte[AES.BLOCK_SIZE];
            for (int i = 0; i < nBlocks; i++) {             
                INraf.seek(i * 16 + 8); //утсновка указателя для считывания файла
                INraf.read(temp, 0, AES.BLOCK_SIZE); //считывание блока в temp

                counter = ByteBuffer.allocate(8).putInt(i).array();
                System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
                System.arraycopy(counter, 0, nonceAndCounter, 12, 4);

                byte[] k = new byte[AES.BLOCK_SIZE]; // k_i

                mAES.encrypt(nonceAndCounter, k);

                byte[] c = new byte[AES.BLOCK_SIZE]; //c_i
                for (int j = 0; j < AES.BLOCK_SIZE; j++) { //xor p_i и k_i
                    c[j] = (byte) (temp[j] ^ k[j]);
                }
                OUTraf.write(c);
                
                if((i+1)==nBlocks){
                    if(c[AES.BLOCK_SIZE-1]>0 && c[AES.BLOCK_SIZE-1]<=16) nToDeleteBytes=c[AES.BLOCK_SIZE-1]; //на случай дешифрования с неправильным ключем
                }
            }

            System.out.println("to delete "+nToDeleteBytes);
            OUTraf.setLength(OUTraf.length()-nToDeleteBytes);
            
            OUTraf.close();
            INraf.close();
        } catch (FileNotFoundException ex) {
            Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        
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
    
    private void PKCS(File f) {
        int n = countDeltaBlocks(f); //сколько байт нужно добавить и какое у них будет значение
        if (n == 0) {
            n = 16; //если сообщение было кратно размеру блока то в конце добавляется блок байтов со значением 16
        }
        try {
            byte[] appendBytes = new byte[n];
            for (int i = 0; i < n; i++) {
                appendBytes[i] = (byte) n;
            }
            appendToFile(f, appendBytes);
        } catch (IOException ex) {
            Logger.getLogger(AESEncryptor.class.getName()).log(Level.SEVERE, null, ex);
        }

    }
    
    private void appendToFile(File f,byte[] b) throws FileNotFoundException, IOException{ //добавить блок байт в конец файла
        RandomAccessFile raf=new RandomAccessFile(f,"rw");
        raf.seek(raf.length());
        raf.setLength(raf.length()+b.length);
        raf.write(b);             
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
    
    public int countBlocks(File f) { //подсчет целых блоков
        return (int) (f.length() / AES.BLOCK_SIZE);
    }
    
    private byte[] readBytesFromFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }
    
    private byte[] readBytesFromFile(File f, int from,int to) throws FileNotFoundException, IOException{
        RandomAccessFile raf=new RandomAccessFile(f, "r");
        raf.seek(from);        
        byte[] res=new byte[to-from];
        raf.read(res, 0, to-from);
        
        raf.close();
        return res;
    }

}
