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
    Button openOriginalFileButton;
    @FXML
    Button saveAsOriginalFileButton;

    public MainController() {
    }

    @FXML
    public void initialize() {
        fileChooser = new FileChooser();

        openOriginalFileButton.setOnAction((event) -> {
            openFile(originalFilePath, originalFileTextArea);
        });
        
        saveAsOriginalFileButton.setOnAction((event)->{
            saveAsfile(originalFilePath, originalFileTextArea);
        });

    }

    @FXML
    private void openFile(TextField pathTextField, TextArea contentTextArea) {
        File file = fileChooser.showOpenDialog(stage);
        if (file != null) {           

            updateFileInfo(pathTextField, contentTextArea, file);
            originalFile=file;
        }
    }

    public void setMainApp(MainApp mainApp) {
        this.mainApp = mainApp;
    }

    private void saveAsfile(TextField pathTextField, TextArea contentTextArea) {
        File file=fileChooser.showSaveDialog(stage);
        if(file!=null){
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
    
    private void updateFileInfo(TextField pathTextField, TextArea contentTextArea,File file){
        try {
                pathTextField.setText(file.getCanonicalPath());
                String content = new String(Files.readAllBytes(file.toPath()));
                contentTextArea.setText(content);

            } catch (IOException ex) {
                Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, null, ex);
            }
    }
}
