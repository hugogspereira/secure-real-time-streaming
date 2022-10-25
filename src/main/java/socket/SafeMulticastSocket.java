package socket;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.MulticastSocket;

public class SafeMulticastSocket extends MulticastSocket{

    public SafeMulticastSocket(int parseInt, InetSocketAddress addr, String string, String server) throws IOException {
        super(parseInt);
    }
    
}
