package com.evgeniy_mh.simpleaescipher.AESEngine;


import java.nio.ByteBuffer;
import java.util.Arrays;

/**
 * Created by evgeniy on 08.04.17.
 */
public class AESEncryptor {

    private AES mAES;

    public AESEncryptor(){
        mAES=new AES();
    }

    /*public byte[] encrypt(byte[] message, byte[] key){
        
        System.out.println("Nonce="+getNonce());
        
        byte[] nonce=ByteBuffer.allocate(8).putInt(getNonce()).array();
        byte[] counter=ByteBuffer.allocate(8).putInt(0).array();        
        byte[] nonceAndCounter=new byte[AES.BLOCK_SIZE]; //используется в раундах
        byte[] nonceAndCounterInfo=new byte[8]; //8 байт которые добавл в начало сообщения и несут инфу о nonce и counter
        System.arraycopy(nonce, 0, nonceAndCounterInfo, 0, 4);
        System.arraycopy(counter, 0, nonceAndCounterInfo, 4, 4);
        
        int n=0; //сколько байт будет добавлено   
        if(message.length%AES.BLOCK_SIZE!=0){ 
            n=AES.BLOCK_SIZE-message.length%AES.BLOCK_SIZE; //сколько байт будет добавлено
            message=PKCS7(message);        
        }
        if(key.length%AES.BLOCK_SIZE!=0) key=PKCS7(key);
        
        mAES.makeKey(key, 128, AES.DIR_BOTH);

        byte[] res=new byte[8+message.length+1];
        int nBlocks=countBlocks(message); //сколько блоков открытого текста

        byte[] temp;
        for(int i=0; i<nBlocks;i++) {

            temp=Arrays.copyOfRange(message,i*16,(i+1)*16); //p_i
            counter=ByteBuffer.allocate(8).putInt(i).array();
            System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
            System.arraycopy(counter, 0, nonceAndCounter, 12, 4);
            
            byte[] k=new byte[AES.BLOCK_SIZE]; // k_i
            mAES.encrypt(nonceAndCounter,k);

            byte[] c=new byte[AES.BLOCK_SIZE]; //c_i
            for(int j=0;j<AES.BLOCK_SIZE;j++){ //xor p_i и k_i
                c[j]= (byte) (temp[j]^k[j]);
            }
            for(int j=i*16+8,m=0;j<(i+1)*16+8;j++,m++){ //копирование бит блока в рез. массив
                res[j]=c[m];
            }
        }
        res[res.length-1]=(byte)n;
        System.arraycopy(nonceAndCounterInfo, 0, res, 0, 8); //дбавление 8 байт которые в начало сообщения которые несут инфу о nonce и counter
        return res;
    }*/
    
    public byte[] decrypt(byte[] message, byte[] key){
        int nToDeleteBytes=message[message.length-1];
        System.out.println("то сколько удалить(после дешифр):"+ nToDeleteBytes);
        
        byte[] nonce=new byte[8];  
        System.arraycopy(message, 0, nonce, 0, 4);
        byte[] counter=new byte[8];       
        System.arraycopy(message, 4, counter, 0, 4);        
        
        
        byte[] nonceAndCounter=new byte[AES.BLOCK_SIZE];     
        
        if(key.length%AES.BLOCK_SIZE!=0) key=PKCS7(key);
        mAES.makeKey(key, 128, AES.DIR_BOTH);

        byte[] resAllBlocks=new byte[message.length];
        int n=countBlocks(message); //сколько блоков шифро текста

        byte[] temp;
        for(int i=0; i<n;i++) {

            temp=Arrays.copyOfRange(message,i*16+8,(i+1)*16+8); //p_i
            counter=ByteBuffer.allocate(8).putInt(i).array();
            System.arraycopy(nonce, 0, nonceAndCounter, 4, 8);
            System.arraycopy(counter, 0, nonceAndCounter, 12, 4);
            
            byte[] k=new byte[AES.BLOCK_SIZE]; // k_i

            mAES.encrypt(nonceAndCounter,k);

            byte[] c=new byte[AES.BLOCK_SIZE]; //c_i
            for(int j=0;j<AES.BLOCK_SIZE;j++){ //xor p_i и k_i
                c[j]= (byte) (temp[j]^k[j]);
            }
            for(int j=i*16,m=0;j<(i+1)*16;j++,m++){ //копирование бит блока в рез. массив
                resAllBlocks[j]=c[m];
            }
        }      
        byte[] res=Arrays.copyOfRange(resAllBlocks, 0, resAllBlocks.length-nToDeleteBytes-1-8);        
        return res;
    }

    private byte[] PKCS7(byte[] b){
        int n=AES.BLOCK_SIZE-b.length%AES.BLOCK_SIZE; //сколько байт нужно добавить и какое у них будет значение
        
        byte[] bPadded=new byte[b.length+n];
        
        for(int i=0;i<bPadded.length;i++){
            if(i<b.length){
                bPadded[i]=b[i];
            }else{
                bPadded[i]=(byte)n;
            }
        }        
        return bPadded;
    }
    
    int getNonce(){
        return Nonce.getInstance().getNonce();
    }
    
    static public void debugPrintByteArray(String mes,byte[] array){
        System.out.println(mes);
        for(int i=0;i<array.length;i++)
            System.out.print(String.format("0x%08X",array[i])+" ");
        System.out.println();
    }

    public int countBlocks(byte[] b){
        return b.length/AES.BLOCK_SIZE;
    }

}
