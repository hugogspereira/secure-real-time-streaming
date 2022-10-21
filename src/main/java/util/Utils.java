package util;

import org.w3c.dom.*;
import org.xml.sax.InputSource;
import javax.xml.parsers.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

public class Utils {
    public static final String CONFIG_PATH = "src/main/java/config/properties/";

    public static String createProps(String addr, String configPath) throws Exception {
        // Addr : localhost/127.0.0.1:9999
        // Addr : ...
        // configPath: src/main/java/config/box-cryptoconfig.txt

        // TODO: Pelo que testei esta solucao parece que n vi funcionar pelas tags seram address com pontos e ":"
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Path filePath = Path.of(configPath);
        try {
            //Transforma um ficheiro txt num xml
            String config = Files.readString(filePath);
            System.out.println(config);
            DocumentBuilder builder = factory.newDocumentBuilder();
            StringBuilder xmlStringBuilder = new StringBuilder();
            xmlStringBuilder.append("<?xml version=\"1.0\"?>\n<root>\n");
            xmlStringBuilder.append(config);
            xmlStringBuilder.append("\n</root>");
            StringReader stringReader = new StringReader(xmlStringBuilder.toString());
            Document doc = builder.parse(new InputSource(stringReader.toString()));

            Element root = doc.getDocumentElement();
            NodeList n = root.getElementsByTagName(addr);

            //Cria o ficheiro .properties com o mesmo nome do ficheiro input
            String[] aux = configPath.split("/");
            String filename = aux[aux.length-1].split("\\.")[0] + ".properties";
            FileOutputStream propsFile = new FileOutputStream(CONFIG_PATH + filename);
            propsFile.write(n.item(0).getTextContent().getBytes());
            propsFile.close();

            return filename;
        }
        catch (Exception e) {
            e.printStackTrace();
            throw new Exception("Problems related with config file occurred!\n"+e.getMessage());
        }
    }
}
