package com.evgeniy_mh.simpleaescipher;

import java.awt.Desktop;
import java.io.File;
import java.io.IOException;
import javafx.fxml.FXML;
import javafx.scene.control.TextField;
import javafx.stage.FileChooser;
import javafx.stage.Stage;

public class MainController {
    
    
    
    private Stage stage;
    
    private FileChooser fileChooser = new FileChooser();
    private Desktop desktop = Desktop.getDesktop();
    private MainApp mainApp;
    
    @FXML
    TextField originalFilePath;
    
    public MainController(){        
    }
    
    @FXML
    public void initialize() {
        fileChooser = new FileChooser();
    }    
    
    
    @FXML
    private void openFile(){
        File file = fileChooser.showOpenDialog(stage);
                    if (file != null) {
                        openFile(file);
                    }
    }
    
    private void openFile(File file) {
        //try {
            //desktop.open(file);
            originalFilePath.setText(file.getAbsolutePath());
        //} catch (IOException ex) {
            
        //}
    }
    
    public void setMainApp(MainApp mainApp) {
        this.mainApp = mainApp;
    }
}
