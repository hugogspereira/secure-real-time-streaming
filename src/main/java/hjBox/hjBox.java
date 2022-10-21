package hjBox;

/* hjBox, 22/23
 *
 * This is a very simple emulation of what we can call 
 * setup Box, to receice UDP-based network streams (for exampple
 * streaming sent from a StreamingServer (see the Streaming Server in
 * the provided materials). UDP streaming from the server can support
 * the dissemination of encoded movies, sent with encoded frames and 
 * sent by teh Streaming Server frame by frame in real time, 
 * for real-time visualization.
 * The emulated Box is able to receive and process the received streamed 
 * frames and can resend these frames in real time for user visualization.
 * The visualization can be done by any tool that can process and play
 * FFMPEG frames received as UDO network streams from the proxy. We
 * suggest the use of an open source tool, such as VLC for this purpose.
 *
 * The hjProxy working as a proxy between the StreamingServer and the 
 * visualization tool must be listening on a remote source (endpoint used by
 * the StreamingServer server) as UDP sender, and can transparently 
 * forward received datagram packets carrying movie frames in the
 * delivering endpoint where the visualizatuon tool (VLC) is expecting.
 *
 * hjBox has a configuration file, with the following setup info
 * See the file "config.properties"
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 */

import java.io.FileInputStream;
import java.net.*;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;
import java.io.InputStream;
import socket.SafeDatagramSocket;

public class hjBox {
    // TODO: Vai passar a ter config.properties e boxCryptoConfig
    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream(args[0]);
        if (inputStream == null) {
            System.out.println("Erro, usar: myBox <config> <box-config>");
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
	    String remote = properties.getProperty("remote");
        String destinations = properties.getProperty("localdelivery");

        SocketAddress inSocketAddress = parseSocketAddress(remote);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s)).collect(Collectors.toSet());

	    SafeDatagramSocket inSocket = new SafeDatagramSocket(inSocketAddress, args[1]);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
 	        inSocket.receive(inPacket);  // if remote is unicast

            System.out.print("*");
            // TODO: Verificar a integridade do packet, se não estiver bem descarta-se e não se envia
            for (SocketAddress outSocketAddress : outSocketAddressSet)
            {
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
          }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) 
    {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
