package util;

import java.util.List;

import org.bouncycastle.asn1.ocsp.TBSRequest;

import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;


public class ConfigReader {

    //path - localizacao do ficheiro que vamos ler
    //target - elemento que estamos a procurar
    public static void read(String path, String target){
        try {
            String aux = new StringBuilder(target).insert(0, "<").append(">").toString();
            List<String> lines = Files.readAllLines(Paths.get(path));
            
            int index = lines.indexOf(aux);
            if(index == -1)
                throw new Exception("target not found");
            
            String[] temp = path.split("/");
            String filename = temp[temp.length-1].split("\\.")[0] + ".properties";
            FileOutputStream propsFile = new FileOutputStream("src/main/java/config/" + filename);
            boolean finished = false;
            for (int i = index+1; i < lines.size() && !finished; i++) {
                aux = lines.get(i);
                
                if(aux.contains(target)){
                    finished = true;
                }
                else{
                    propsFile.write(aux.getBytes());
                }
            }
            propsFile.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
