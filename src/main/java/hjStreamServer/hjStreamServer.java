package hjStreamServer;

/* hjStreamServer.java
* Streaming server: streams video frames in UDP packets
* for clients to play in real time the transmitted movies
*/

import java.io.*;
import java.io.FileInputStream;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import socket.SafeDatagramSocket;

public class hjStreamServer {
	// TODO: Vai passar a ter moviesCryptoConfig e boxCryptoConfig
	static public void main( String []args ) throws Exception {
		if (args.length != 4) {
				System.out.println("Erro, usar: mySend <movie> <ip-multicast-address> <port> <movies-config>");
	           	System.out.println("        or: mySend <movie> <ip-unicast-address> <port> <movies-config>");
	           	System.exit(-1);
			}
			int size;
			int count = 0;
			long time;
			DataInputStream g = new DataInputStream( new FileInputStream(args[0]) );
			byte[] buff = new byte[4096];

			InetSocketAddress addr = new InetSocketAddress( args[1], Integer.parseInt(args[2]));
			SafeDatagramSocket s = new SafeDatagramSocket(addr, args[3]);
			DatagramPacket p = new DatagramPacket(buff, buff.length, addr );
			long t0 = System.nanoTime(); // tempo de referencia para este processo
			long q0 = 0;

			while ( g.available() > 0 ) {
				size = g.readShort();
				time = g.readLong();
				if ( count == 0 ) q0 = time;
				count += 1;
				g.readFully(buff, 0, size );
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
