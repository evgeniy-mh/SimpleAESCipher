package com.evgeniy_mh.simpleaescipher;

import java.awt.Desktop;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
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

    public MainController() {
    }

    @FXML
    public void initialize() {
        fileChooser = new FileChooser();

        createOriginalFile.setOnAction((event) -> {
            File f=createNewFile(originalFilePath, originalFileTextArea);
            if(f!=null) originalFile=f;
        });
        
        openOriginalFile.setOnAction((event) -> {
            File f= openFile(originalFilePath, originalFileTextArea);
            if(f!=null) originalFile=f;
        });
        
        saveOriginalFile.setOnAction((event)->{
            saveFile(originalFilePath, originalFileTextArea, originalFile);
        });

        saveAsOriginalFile.setOnAction((event) -> {
            saveAsfile(originalFilePath, originalFileTextArea);
        });

    }
    
    @FXML
    private File createNewFile(TextField pathTextField, TextArea contentTextArea){
        File file = fileChooser.showSaveDialog(stage);
        if(file!=null){   
            try {
                FileWriter fw;
                fw = new FileWriter(file);
                fw.write("");
                fw.close();
                
                updateFileInfo(pathTextField, contentTextArea, file);
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return file;
    }

    @FXML
    private File openFile(TextField pathTextField, TextArea contentTextArea) {
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {
            updateFileInfo(pathTextField, contentTextArea, file);
        }
        return file;
    }

    public void setMainApp(MainApp mainApp) {
        this.mainApp = mainApp;
    }

    private void saveFile(TextField pathTextField, TextArea contentTextArea, File textFile) {
        if (textFile != null) {
            try {
                FileWriter fw;
                fw = new FileWriter(textFile);
                fw.write(contentTextArea.getText());
                fw.close();
                
                updateFileInfo(pathTextField, contentTextArea, textFile);
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    private void saveAsfile(TextField pathTextField, TextArea contentTextArea) {
        File file = fileChooser.showSaveDialog(stage);
        if (file != null) {
            try {
                FileWriter fw;
                fw = new FileWriter(file);
                fw.write(contentTextArea.getText());
                fw.close();

                updateFileInfo(pathTextField, contentTextArea, file);
            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
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
}
