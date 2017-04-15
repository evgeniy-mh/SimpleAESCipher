package com.evgeniy_mh.simpleaescipher;

import com.evgeniy_mh.simpleaescipher.AESEngine.AESEncryptor;
import java.awt.Desktop;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.util.logging.Level;
import java.util.logging.Logger;
import javafx.fxml.FXML;
import javafx.scene.control.Button;
import javafx.scene.control.TextArea;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainController {

    private Stage stage;

    private FileChooser fileChooser = new FileChooser();
    private Desktop desktop = Desktop.getDesktop();
    private MainApp mainApp;

    private File originalFile;
    private byte[] originalFileBytes;
    @FXML
    TextField originalFilePath;
    @FXML
    TextArea originalFileTextArea;
    @FXML
    Button createOriginalFile;
    @FXML
    Button openOriginalFile;
    @FXML
    Button saveOriginalFile;
    @FXML
    Button saveAsOriginalFile;

    private File resultFile;
    private byte[] resultFileBytes;
    @FXML
    TextField resultFilePath;
    @FXML
    TextArea resultFileTextArea;
    @FXML
    Button createResultFile;
    @FXML
    Button openResultFile;
    @FXML
    Button saveAsResultFile;

    @FXML
    TextField keyTextField;
    @FXML
    Button encryptButton;
    @FXML
    Button decryptButton;

    AESEncryptor mAESEncryptor;

    public MainController() {
    }

    @FXML
    public void initialize() {
        mAESEncryptor = new AESEncryptor();
        fileChooser = new FileChooser();

        createOriginalFile.setOnAction((event) -> {
            File f = createNewFile();
            if (f != null) {
                originalFile = f;
                originalFileBytes = readBytesFromFile(f);
                updateFileInfo(originalFilePath, originalFileTextArea, f);
            }
            mAESEncryptor.debugPrintByteArray("opened file: ", originalFileBytes);
        });

        openOriginalFile.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                originalFile = f;
                originalFileBytes = readBytesFromFile(f);
                updateFileInfo(originalFilePath, originalFileTextArea, f);
            }
            mAESEncryptor.debugPrintByteArray("opened file: ", originalFileBytes);
        });

        saveOriginalFile.setOnAction((event) -> {
            saveFile(originalFile, originalFileBytes);
            updateFileInfo(originalFilePath, originalFileTextArea, originalFile);

            mAESEncryptor.debugPrintByteArray("saved file: ", originalFileBytes);
        });

        saveAsOriginalFile.setOnAction((event) -> {
            saveAsfile(originalFileBytes);
        });

        createResultFile.setOnAction((event) -> {
            /*File f = createNewFile(resultFilePath, resultFileTextArea);
            if (f != null) {
                resultFile = f;
            }*/
        });

        openResultFile.setOnAction((event) -> {
            File f = openFile();
            if (f != null) {
                resultFile = f;
                resultFileBytes = readBytesFromFile(f);
                updateFileInfo(resultFilePath, resultFileTextArea, f);
            }
            mAESEncryptor.debugPrintByteArray("opened file: ", resultFileBytes);
        });

        saveAsResultFile.setOnAction((event) -> {
            saveAsfile(resultFileBytes);
        });
        
        encryptButton.setOnAction((event)->{
            encrypt();
        });
        
        decryptButton.setOnAction((event)->{
            decrypt();
        });

    }

    @FXML
    private File createNewFile() {
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            try {
                FileWriter fw;
                fw = new FileWriter(file);
                fw.write("");
                fw.close();

                //updateFileInfo(pathTextField, contentTextArea, file);
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return file;
    }

    @FXML
    private File openFile() {
        File file = fileChooser.showOpenDialog(stage);
        /*if (file != null) {
            updateFileInfo(pathTextField, contentTextArea, file);
        }*/
        return file;
    }

    public void setMainApp(MainApp mainApp) {
        this.mainApp = mainApp;
    }

    private void saveFile(File file, byte[] fileBytes) {
        if (file != null && fileBytes != null) {
            try {
                FileOutputStream fos = new FileOutputStream(file);
                fos.write(fileBytes);
                fos.close();
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private File saveAsfile(byte[] fileBytes) {
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {

            saveFile(file, fileBytes);

        }
        return file;
    }

    private void updateFileInfo(TextField pathTextField, TextArea contentTextArea, File file) {
        //System.out.println(file);

        try {
            pathTextField.setText(file.getCanonicalPath());
            String content = new String(Files.readAllBytes(file.toPath()));
            contentTextArea.setText(content);

        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private byte[] readBytesFromFile(File file) {
        try {
            return Files.readAllBytes(file.toPath());
        } catch (IOException ex) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }
    }

    private void encrypt() {
        if(!getKey().isEmpty() && originalFileBytes!=null)
        try {
            resultFileBytes = mAESEncryptor.encrypt(originalFileBytes, getKey().getBytes("UTF-8"));
            resultFile= saveAsfile(resultFileBytes);
            updateFileInfo(resultFilePath, resultFileTextArea, resultFile);
            
        } catch (UnsupportedEncodingException ex) {

        }
    }
    
    private void decrypt(){
        if(!getKey().isEmpty() && resultFileBytes!=null)
        try {
            originalFileBytes = mAESEncryptor.decrypt(resultFileBytes, getKey().getBytes("UTF-8"));
            originalFile= saveAsfile(originalFileBytes);
            updateFileInfo(originalFilePath, originalFileTextArea, originalFile);
            
        } catch (UnsupportedEncodingException ex) {

        }
    }

    private String getKey() {
        return keyTextField.getText();
    }
}
