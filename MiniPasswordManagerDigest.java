/*********************************************************************** 
  MiniPasswordManager.java 

  Copyright (C) 2006 Neil Daswani 

  This class implements a MiniPasswordManager that can be used by 
  other applications. You must call init() prior to calling 
  checkPassword(), or add(). 

  This file is also available at http://www.learnsecurity.com/ntk 
***********************************************************************/ 

package assignment3; 

import java.util.*; 
import java.io.*; 
import java.security.*;
import java.math.*;  

public class MiniPasswordManagerDigest { 

     /** userMap is a Hashtable keyed by username, and has 
         HashedPasswordTuples as its values */ 
   private static Hashtable dUserMap; 

     /** location of the password file on disk */ 
   private static String dPwdFile; 

     /** chooses a salt for the user, computes the salted hash 
         of the user's password, and adds a new entry into the 
         userMap hashtable for the user. */ 
   public static void add(String username, 
                            String password) throws Exception { 
      int salt = 1457736876; //chooseNewSalt(); 
      HashedPasswordTuple ur = 
                    new HashedPasswordTuple(getHash(username,password), salt); 
      dUserMap.put(username,ur);
      System.out.println("Null test " + dUserMap.get(username).toString()); 
   } 

     /** returns a salted, MD5 hash of the password */
   public static String getHash(String usn, String pwd) throws Exception { 
      return computeMD5(usn + ":DigestAuthWebServer:" + pwd); 
   } 

     /** returns the SHA-256 hash of the provided preimage as a String */ 
   private static String computeMD5(String preimage) throws Exception { 
   
      MessageDigest md = MessageDigest.getInstance("MD5");
      md.reset();
      md.update(preimage.getBytes());
      byte[] raw = md.digest();
      BigInteger bigInt = new BigInteger(1,raw);
      return bigInt.toString(16); 
   } 

     /** returns true iff the username and password are in the database */
   public static boolean checkPassword(String username, String response, int nonce, String uri, String method) {
      System.out.println("Check password: "+ username + "," + nonce + "," + uri + "," + method);
      try {
         System.out.println(dUserMap.get(username));              
         HashedPasswordTuple t = (HashedPasswordTuple)dUserMap.get(username);
         System.out.println(t); 
         return (t == null) ? false :  
                    response.equals(computeResponse(t.getHashedPassword(), nonce, uri, method)); 
      } 
      catch (Exception e) {
         System.out.println(e); 
      } 
      return false; 
   }
     
   public static String computeResponse(String storedHash, int nonce, String uri, String method)
   {
      System.out.println("We made it!");
      try {    
         byte raw[];
         String h2 = method + ":" + uri;
         
         MessageDigest md = MessageDigest.getInstance("MD5");
         md.reset();
         md.update(h2.getBytes());
         raw = md.digest();
         BigInteger bigInt = new BigInteger(1,raw);
         h2 = bigInt.toString(16); 
         
         String returnResponse = storedHash + ":" + nonce + ":" + h2;
         md = MessageDigest.getInstance("MD5");
         md.reset();
         md.update(returnResponse.getBytes());
         raw = md.digest();
         bigInt = new BigInteger(1,raw);
         returnResponse = bigInt.toString(16); 
         
         
         System.out.println(returnResponse); 
         return returnResponse;
      }
      catch(Exception e){
         return "";
      }
   }       

     /** Password file management operations follow **/ 
   public static void init(String pwdFile) throws Exception { 
      dUserMap = HashedSaltedPasswordFile.load(pwdFile); 
      dPwdFile = pwdFile; 
   } 

    /** forces a write of the password file to disk */
   public static void flush() throws Exception { 
      HashedSaltedPasswordFile.store (dPwdFile, dUserMap); 
   } 

     /** adds a new username/password combination to the database, or
         replaces an existing one. */
   public static void main(String argv[]) { 
      String pwdFile = null; 
      String userName = null; 
      try { 
         pwdFile = argv[0]; 
         userName = argv[1]; 
         init(pwdFile); 
         System.out.print("Enter new password for " + userName + ": "); 
         BufferedReader br = 
                    new BufferedReader(new InputStreamReader(System.in)); 
         String password = br.readLine(); 
         add(userName, password); 
         flush(); 
      } 
      catch (Exception e) { 
         if ((pwdFile != null) && (userName != null)) { 
            System.err.println("Error: Could not read or write " + pwdFile); 
         } 
         else { 
            System.err.println("Usage: java " +     
                                       "com.learnsecurity.MiniPasswordManager" + 
                                       " <pwdfile> <username>"); 
         } 
      } 
   } 
}

/** This class is a simple container that stores a salt, and a 
    salted, hashed passsord.  */
class HashedPasswordTuple { 
   private String dHpwd; 
   private int dSalt; 
   public HashedPasswordTuple(String p, int s) { 
      dHpwd = p; dSalt = s; 
   } 

     /** Constructs a HashedPasswordTuple pair from a line in
         the password file. */
   public HashedPasswordTuple(String line) throws Exception { 
      StringTokenizer st = 
               new StringTokenizer(line, HashedSaltedPasswordFile.DELIMITER_STR); 
      dHpwd = st.nextToken(); // hashed + salted password 
      dSalt = Integer.parseInt(st.nextToken()); // salt 
   } 

   public String getHashedPassword() { 
      return dHpwd; 
   } 

   public int getSalt() { 
      return dSalt; 
   } 

     /** returns a HashedPasswordTuple in string format so that it
         can be written to the password file. */
   public String toString () { 
      return (dHpwd + HashedSaltedPasswordFile.DELIMITER_STR + (""+dSalt)); 
   } 
}

/** This class extends a HashedPasswordFile to support salted, hashed passwords. */
class HashedSaltedPasswordFile extends HashedPasswordFile { 

     /* The load method overrides its parent.FN"s, as a salt also needs to be
        read from each line in the password file. */
   public static Hashtable load(String pwdFile) { 
      Hashtable userMap = new Hashtable(); 
      try { 
         FileReader fr = new FileReader(pwdFile); 
         BufferedReader br = new BufferedReader(fr); 
         String line; 
         while ((line = br.readLine()) != null) { 
            int delim = line.indexOf(DELIMITER_STR); 
            String username=line.substring(0,delim); 
            HashedPasswordTuple ur = 
                         new HashedPasswordTuple(line.substring(delim+1)); 
            userMap.put(username, ur);
            System.out.println( 
         } 
      } 
      catch (Exception e) { 
         System.err.println ("Warning: Could not load password file."); 
      } 
      return userMap; 
   } 
}

/** This class supports a password file that stores hashed (but not salted)
    passwords. */
class HashedPasswordFile { 

     /* the delimiter used to separate fields in the password file */ 
   public static final char DELIMITER = ':'; 
   public static final String DELIMITER_STR = "" + DELIMITER; 

     /* We assume that DELIMITER does not appear in username and other fields. */ 
   public static Hashtable load(String pwdFile) { 
      Hashtable userMap = new Hashtable(); 
      try { 
         FileReader fr = new FileReader(pwdFile); 
         BufferedReader br = new BufferedReader(fr); 
         String line; 
         while ((line = br.readLine()) != null) { 
            int delim = line.indexOf(DELIMITER_STR); 
            String username = line.substring(0,delim); 
            String hpwd = line.substring(delim+1); 
            userMap.put(username, hpwd); 
         } 
      } 
      catch (Exception e) { 
         System.err.println ("Warning: Could not load password file."); 
      } 
      return userMap; 
   } 

   public static void store(String pwdFile, Hashtable userMap) throws Exception { 
      try { 
         FileWriter fw = new FileWriter(pwdFile); 
         Enumeration e = userMap.keys(); 
         while (e.hasMoreElements()) { 
            String uname = (String)e.nextElement(); 
            fw.write(uname + DELIMITER_STR +                           
                             userMap.get(uname).toString() + ""); 
         } 
         fw.close(); 
      } 
      catch (Exception e) { 
         e.printStackTrace(); 
      } 
   } 
}
