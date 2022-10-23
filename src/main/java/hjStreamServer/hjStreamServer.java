package hjStreamServer;

/* hjStreamServer.java
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import socket.DataInputDecryptStream;
import socket.SafeDatagramSocket;

public class hjStreamServer {
	// TODO: Vai passar a ter moviesCryptoConfig e boxCryptoConfig
	static public void main( String []args ) throws Exception {
		if (args.length != 5) {
				System.out.println("Erro, usar: mySend <movie> <movies-config> <ip-multicast-address> <port> <box-config>");
	           	System.out.println("        or: mySend <movie> <movies-config> <ip-unicast-address> <port> <box-config>");
	           	System.exit(-1);
			}
			int size;
			int count = 0;
			long time;
			DataInputStream g = (new DataInputDecryptStream( args[0], args[1]).getDataInputStream());
			byte[] buff = new byte[4 * 1024];

			InetSocketAddress addr = new InetSocketAddress( args[2], Integer.parseInt(args[3]));
			SafeDatagramSocket s = new SafeDatagramSocket(addr, args[4]);
			DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
			long t0 = System.nanoTime(); // tempo de referencia para este processo
			long q0 = 0;

			while ( g.available() > 0 ) {
				size = g.readShort();
				time = g.readLong();
				if ( count == 0 ) q0 = time;
				count += 1;
				g.readFully(buff, 0, size);
				p.setData(buff, 0, size );
				p.setSocketAddress( addr );
				long t = System.nanoTime();
				Thread.sleep( Math.max(0, ((time-q0)-(t-t0))/1000000) );
		   
		        // send packet (with a frame payload)
			    s.send(p);
			    System.out.print( "." );
		}

		System.out.println("DONE! all frames sent: "+count);
	}

}
