package util;

import java.util.List;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;


public class ConfigReader {

    public static final String CONFIG_PATH = "src/main/java/config/";
    //path - localizacao do ficheiro que vamos ler
    //target - elemento que estamos a procurar
    public static String read(String path, String target) throws Exception {
        System.out.println(path);
        System.out.println(target);

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
            String[] line;
            for (int i = index+1; i < lines.size() && !finished; i++) {
                aux = lines.get(i);

                if(aux.contains(target)){
                    finished = true;
                }
                else{
                    line = aux.split(":");
                    aux = line[0].toUpperCase()+": "+line[1];

                    propsFile.write(aux.getBytes());
                    propsFile.write("\n".getBytes());
                }
            }
            propsFile.close();

            return filename;
        }
        catch (Exception e) {
            throw new Exception("Problems related with config file occurred!\n"+e.getMessage());
        }
    }
}
