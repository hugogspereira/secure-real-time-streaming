package util;

import org.w3c.dom.*;

/**
 * Material/Labs para SRSC 20/21, Sem-1
 * hj
 **/

import org.xml.sax.InputSource;

import javax.xml.parsers.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Auxiliar
 * Some conversion functions
 */
public class Utils {
    private static String digits = "0123456789abcdef";

    /**
     * Return string hexadecimal from byte array of certain size
     * 
     * @param data   : bytes to convert
     * @param length : nr of bytes in data block to be converted
     * @return hex : hexadecimal representation of data
     */

    public static String toHex(byte[] data, int length) {
        StringBuffer buf = new StringBuffer();

        for (int i = 0; i != length; i++) {
            int v = data[i] & 0xff;

            buf.append(digits.charAt(v >> 4));
            buf.append(digits.charAt(v & 0xf));
        }

        return buf.toString();
    }

    /**
     * Return data in byte array from string hexadecimal
     * 
     * @param data : bytes to be converted
     * @return : hexadecimal repersentatin of data
     */
    public static String toHex(byte[] data) {
        return toHex(data, data.length);
    }

    public static String createProps(String path) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        Path filePath = Path.of(path);
        try {
            //Este bloco de codigo basicamente transforma um ficehiro txt num xml
            String config = Files.readString(filePath);                                                       
            DocumentBuilder builder = factory.newDocumentBuilder();                                           
            StringBuilder xmlStringBuilder = new StringBuilder();                                             
            xmlStringBuilder.append("<?xml version=\"1.0\"?>\n<root>");
            xmlStringBuilder.append(config);
            xmlStringBuilder.append("</root>");
            Document doc = builder.parse(new InputSource(new StringReader(xmlStringBuilder.toString()))); 

            Element root = doc.getDocumentElement();
            //TODO adicionar forma de encontrar fime que queremos. O metodo pode possivelmente recber como parametro o que procura assim funcionara para o hjbox tambem.
            NodeList n = root.getElementsByTagName("monsters.dat.encrypted");

            //Este bloco de codigo serve para criar o ficeito .properties com o mesmo nome do ficheiro input
            String[] aux = path.split("/");
            String filename = aux[aux.length-1].split("\\.")[0] + ".properties";
            FileOutputStream propsFile = new FileOutputStream("src/main/java/config/" + filename); //o ficheiro criado e guardado no config folder
            propsFile.write(n.item(0).getTextContent().getBytes());
            propsFile.close();

            return filename; //devolve o nome do ficheiro criado para que o SafeSocket consiga encontra lo 
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }
}
