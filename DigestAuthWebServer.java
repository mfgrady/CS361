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
    }                                            
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
   String username = null, realm = null, uri = null;                  	 
    
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
      Credentials c;

    	String header = null;
    	while (!(header = br.readLine()).equals("")) {
   	 System.err.println (header);
   	 if (header.startsWith("Authorization:")) {
   	 	StringTokenizer st = new StringTokenizer(header, "\"");   	 
    
         
        	st.nextToken();
     	   username = st.nextToken();
        	st.nextToken();
        	realm = st.nextToken();
        	st.nextToken();
        	st.nextToken();
        	st.nextToken();
        	uri = st.nextToken();
        	st.nextToken();
        	response = st.nextToken();
            	        	
       }
      }
      
      c = new Credentials(username,response);
      
      System.out.println(c);  
  	 
      //Generate nonce  	 
   	//SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
   	int nonce = 123456;//Math.abs(sr.nextInt());       	 
  	 
  	 
    	if ((c != null) && (MiniPasswordManagerDigest.checkPassword(c.getUsername(), c.getResponse(), nonce, uri, command))) {
                     	 
                                             	 
   	 serveFile(osw, pathname);
    	} else {
      
      //sr = SecureRandom.getInstance("SHA1PRNG");
   	//nonce = Math.abs(sr.nextInt()); 
 	 
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
	private String dResponse;

	public Credentials(String usn, String rsp) throws Exception {
  	   dUsername = usn;  dResponse = rsp;
  	 
	}
	public String getUsername() {
    return dUsername;
	}
	public String getResponse() {
    return dResponse;
	}
   
   public String toString(){
      return ("Values: " + dUsername + " : " + dResponse);
      }
	
}



