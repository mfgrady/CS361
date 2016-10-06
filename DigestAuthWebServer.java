/***********************************************************************

   SimpleWebServer.java


   This toy web server is used to illustrate security vulnerabilities.
   This web server only supports extremely simple HTTP GET requests.

   This file is also available at http://www.learnsecurity.com/ntk

***********************************************************************/

package assignment3;                           	 

import java.io.*;                                    	 
import java.net.*;                                   	 
import java.util.*;
import java.security.*;                                   	 
import sun.misc.BASE64Decoder;

public class DigestAuthWebServer {                       	 

	/* Run the HTTP server on this TCP port. */      	 
	private static final int PORT = 8080;            	 

	/* The socket used to process incoming connections
   	from web clients */
	private static ServerSocket dServerSocket;       	 
 
	public DigestAuthWebServer () throws Exception {     	 
    dServerSocket = new ServerSocket (PORT);     	 
	}                                                	 

	public void run() throws Exception {            	 
    while (true) {                              	 
    	/* wait for a connection from a client */
    	Socket s = dServerSocket.accept();      	 

    	/* then process the client's request */
    	processRequest(s);                      	 
    }                                            	.
	}                                               	 

	private String checkPath (String pathname) throws Exception {
    File target = new File (pathname);
    File cwd = new File (System.getProperty("user.dir"));
    String s1 = target.getCanonicalPath();
    String s2 = cwd.getCanonicalPath();
    
    if (!s1.startsWith(s2))
    	throw new Exception();
    else
    	return s1;
	}

	/* Reads the HTTP request from the client, and
   	responds with the file the user requested or
   	a HTTP error code. */
	public void processRequest(Socket s) throws Exception {
    /* used to read data from the client */
    BufferedReader br =                            	 
    	new BufferedReader (
   			 new InputStreamReader (s.getInputStream()));

    /* used to write data to the client */
    OutputStreamWriter osw =                       	 
    	new OutputStreamWriter (s.getOutputStream());  
    
    /* read the HTTP request from the client */
    String request = br.readLine();               	 

    String command = null;                        	 
    String pathname = null;
   String response = null;                   	 
    
    try {
    	/* parse the HTTP request */
    	StringTokenizer st =
   	 new StringTokenizer (request, " ");          	 
    	command = st.nextToken();                  	 
    	pathname = st.nextToken();                 	 
    } catch (Exception e) {
    	osw.write ("HTTP/1.0 400 Bad Request\n\n");
    	osw.close();
    	return;
    }

    if (command.equals("GET")) {	 
         	 
    	Credentials c = getAuthorization(br);
  	 
  	 
  	 
   	SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
   	int nonce = Math.abs(sr.nextInt());       	 
  	 
  	 
    	if ((c != null) && (MiniPasswordManager.checkPassword(c.getUsername(),
   							   c.getPassword()))) {
                     	 
  	response = c.getResponse(nonce);
   	 System.err.println(response);
                                             	 
   	 serveFile(osw, pathname);
    	} else {
 	 
  	    osw.write ("HTTP/1.0 401 Unauthorized\n");
   	 osw.write ("WWW-Authenticate: Digest realm=\"DigestAuthWebServer\", nonce =\"" + nonce + "\" \n\n");
 	 
    	}
    } else {                                    	 
    	/* if the request is a NOT a GET,
       	return an error saying this server
       	does not implement the requested command */
    	osw.write ("HTTP/1.0 501 Not Implemented\n\n");
    }                                          	 
    
    /* close the connection to the client */
    osw.close();                               	 
	}                                              	 

	private Credentials getAuthorization (BufferedReader br) {
    try {
    	String header = null;
    	while (!(header = br.readLine()).equals("")) {
   	 System.err.println (header);
   	 if (header.startsWith("Authorization:")) {
   	 	StringTokenizer st = new StringTokenizer(header, "\"");
   	 	return new Credentials(st);
   	 }
    	}
    } catch (Exception e) {
    }
    return null;
	}

	public void serveFile (OutputStreamWriter osw, 	 
                       	String pathname) throws Exception {
    FileReader fr=null;                            	 
    int c=-1;                                      	 
    StringBuffer sb = new StringBuffer();
 	 
    /* remove the initial slash at the beginning
   	of the pathname in the request */
    if (pathname.charAt(0)=='/')                   	 
    	pathname=pathname.substring(1);            	 
    
    /* if there was no filename specified by the
   	client, serve the "index.html" file */
    if (pathname.equals(""))                       	 
    	pathname="index.html";                     	 

    /* try to open file specified by pathname */
    try {                                          	 
    	fr = new FileReader (checkPath(pathname));            	 
    	c = fr.read();                             	 
    }                                              	 
    catch (Exception e) {                          	 
    	/* if the file is not found,return the
       	appropriate HTTP response code  */
    	osw.write ("HTTP/1.0 404 Not Found\n\n");    	 
    	return;                                    	 
    }                                              	 

    /* if the requested file can be successfully opened
   	and read, then return an OK response code and
   	send the contents of the file */
    osw.write ("HTTP/1.0 200 OK\n\n");               	 
    while (c != -1) {  	 
        	sb.append((char)c);                       	 
    	c = fr.read();                             	 
    }                                              	 
    osw.write (sb.toString());                             	 
	}                                                  	 

	/* This method is called when the program is run from
   	the command line. */
	public static void main (String argv[]) throws Exception {
    if (argv.length == 1) {
    	/* Initialize MiniPasswordManager */
    	MiniPasswordManager.init(argv[0]);

    	/* Create a DigestAuthWebServer object, and run it */
    	DigestAuthWebServer baws = new DigestAuthWebServer();      	 
    	baws.run();                                        	 
    } else {
    	System.err.println ("Usage: java DigestAuthWebServer <pwdfile>");
    }
	}                                                     	 
}                                                         	 

class Credentials {
	private String dUsername;
	private String dPassword;
	private String response;
	public Credentials(StringTokenizer st) throws Exception {
  	String realm, uri, response, nonce;
  	st.nextToken();
  	 dUsername = st.nextToken();
  	st.nextToken();
  	realm = st.nextToken();
  	st.nextToken();
  	nonce = st.nextToken();
  	st.nextToken();
  	uri = st.nextToken();
  	st.nextToken();
  	response = st.nextToken();
  	System.out.println("Username is: " + dUsername);
  	System.out.println("Realm is: " + realm);
  	System.out.println("URI is: " + uri);
  	System.out.println("Response is: " + response);
 	 
  	String responseTest = new String((new sun.misc.BASE64Decoder().decodeBuffer(response)));
 	 
  	System.out.println("Decoded Response: " + responseTest);
  	 
	}
	public String getUsername() {
    return dUsername;
	}
	public String getPassword() {
    return dPassword;
	}
	public String getResponse(int nonce) {
 
  	try{
  	   MessageDigest md = MessageDigest.getInstance("MD5");
   	byte raw[];
    	String h1 = "\"" + this.getUsername()+ ":DigestAuthWebServer:" + this.getPassword()+"\"";
   	md.update(h1.getBytes("UTF-8"));
   	raw = md.digest();
   	h1 = new sun.misc.BASE64Encoder().encode(raw);
   	String h2 = "GET:/";
   	md.update(h2.getBytes("UTF-8"));
   	raw = md.digest();
   	h2 = new sun.misc.BASE64Encoder().encode(raw);
  	 
   	String response = "\"" + h1 + ":" + nonce + ":" + h2 + "\"";
   	md.update(response.getBytes("UTF-8"));
   	raw = md.digest();
   	return (new sun.misc.BASE64Encoder().encode(raw));
   	} catch (Exception e) {
    	return "";
   	}
	}
}



