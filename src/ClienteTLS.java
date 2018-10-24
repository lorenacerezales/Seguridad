import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.security.KeyStore;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/****************************************************************************
* This example shows how to set up a key manager to do client
* authentication if required by server.
*
* This program assumes that the client is not inside a firewall.
* The application can be modified to connect to a server outside
* the firewall by following SSLSocketClientWithTunneling.java.
* 
****************************************************************************/
public class ClienteTLS {

private static String 	raizMios     = "C:/Users/Administrador/Documents/";

public static void main(String[] args) throws Exception {
 
 String 	host 				= null;
 int 		port 				= -1;
 String 	path 				= null;
 char[] 	contraseña 		  	= "123456".toCharArray();
 char[] 	contraseñaEntrada 	= "123456".toCharArray();
 String[]   cipherSuites = null;
	    
 
 definirKeyStoresMios();

 for (int i = 0; i < args.length; i++)
     System.out.println(args[i]);

 if (args.length < 3) {
     System.out.println(
         "USAGE: java SSLSocketClientWithClientAuth " +
         "host port requestedfilepath");
     System.exit(-1);
 }

 try {
     host = args[0];
     port = Integer.parseInt(args[1]);
     path = args[2];
 } catch (IllegalArgumentException e) {
      System.out.println("USAGE: java SSLSocketClientWithClientAuth " +
          "host port requestedfilepath");
      System.exit(-1);
 }

 try {

     /*****************************************************************************
      * Set up a key manager for client authentication if asked by the server.  
      * Use the implementation's default TrustStore and secureRandom routines.
      ****************************************************************************/
     SSLSocketFactory factory = null;

     SSLContext 		ctx;
     KeyManagerFactory 	kmf;
     KeyStore 			ks;

     try {
	
	         ctx = SSLContext.getInstance("TLS");   

	         // Definir el/los KeyManager.
	         //    Ahora son necesarios ya que el cliente necesita autenticarnse
	         //    y por tanto al SSL tenemos que informarle de donde tomar las
	         //    credenciales del cliente.
	         //
	         kmf = KeyManagerFactory.getInstance("SunX509");
	         ks = KeyStore.getInstance("JCEKS");
			 ks.load(new FileInputStream(raizMios + "KeyStoreCliente_2017.jce"), contraseña);
	         kmf.init(ks, contraseña);
	         
	         /*  Se inicializa el contexto pasandole:
	          *  
	          *  - el/los KeyManagers creado/s.
	          *  - Usa el TrustManager por defecto (null).
	          *  - Usa el SecureRamdom por defecto (null).
	          */
	         ctx.init(kmf.getKeyManagers(), null, null);
	
	         // Asignamos un socket al contexto.
	         
	         factory = ctx.getSocketFactory();

        	/*********************************************************************
        	 * Suites SSL del contexto
        	 *********************************************************************/
	         System.out.println ("******** CypherSuites Disponibles **********");
 	   	     cipherSuites = factory.getSupportedCipherSuites();
 	   	     for (int i=0; i<cipherSuites.length; i++) 
 	       		System.out.println (cipherSuites[i]);	    
 		   	    
 	   	     // Suites habilitadas por defecto
 	
 	   	     System.out.println ("****** CypherSuites Habilitadas por defecto **********");
 	   	    
 	   	     String[] cipherSuitesDef = factory.getDefaultCipherSuites();
 	   	     for (int i=0; i<cipherSuitesDef.length; i++) 
 	       		 System.out.println (cipherSuitesDef[i]);
     
     
     } catch (Exception e) {
         					throw new IOException(e.getMessage());
     					   }
     
      SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

      System.out.println ("******** CypherSuites Disponibles 2**********");
 	     cipherSuites = factory.getSupportedCipherSuites();
 	     for (int i=0; i<cipherSuites.length; i++) 
     		System.out.println (cipherSuites[i]);	    

     /*-------------------------------------------------------------------------------------
     	 SSLSocketFactory factory =
	    		(SSLSocketFactory)SSLSocketFactory.getDefault();

	    System.out.println ("Crear socket");
	    SSLSocket socket = (SSLSocket) factory.createSocket(args[0], 
	    													Integer.parseInt(args[1]));

      --------------------------------------------------------------------------------------*/
     
     
 /***/
     String[]   cipherSuitesHabilitadas = {"TLS_RSA_WITH_AES_128_CBC_SHA"};
     										
     
	 //cipherSuitesHabilitadas[0] = cipherSuites[0];

	 System.out.println (cipherSuitesHabilitadas[0]);
	 
     
	 socket.setEnabledCipherSuites(cipherSuitesHabilitadas);

 	 System.out.println ("****** CypherSuites Habilitadas en el ssl socket **********");

	 String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
 	 for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
	       		System.out.println (cipherSuitesHabilSocket[i]);
	 
/****/
     /*********************************************************************
      * send http request
      *
      * See SSLSocketClient.java for more information about why
      * there is a forced handshake here when using PrintWriters.
      ********************************************************************/

    System.out.println ("\n*************************************************************");	    
    System.out.println ("  Comienzo SSL Handshake -- Cliente y Server Autenticados");
    System.out.println ("  *************************************************************");	    
   
    socket.startHandshake();
    
    System.out.println ("\n*************************************************************");
    System.out.println ("Fin OK SSL Handshake");
    System.out.println ("\n*************************************************************");
     

     PrintWriter out = new PrintWriter(
                           new BufferedWriter(
                           new OutputStreamWriter(
                           socket.getOutputStream())));
     out.println("GET /" + path + " HTTP/1.1");
     out.println();
     out.flush();

     /*
      * Make sure there were no surprises
      */
     if (out.checkError())
         System.out.println(
             "SSLSocketClient: java.io.PrintWriter error");

     /* read response */
     BufferedReader in = new BufferedReader(
                             new InputStreamReader(
                             socket.getInputStream()));

     String inputLine;

     while ((inputLine = in.readLine()) != null)
         System.out.println(inputLine);

     in.close();
     out.close();
     socket.close();

 } catch (Exception e) {
     e.printStackTrace();
 }
}

/******************************************************
	definirKeyStores()
*******************************************************/
private static void definirKeyStoresMios()
{
	String 	raizMios     = "C:/Users/Administrador/Documents/";

	// Almacen de claves
	
	System.setProperty("javax.net.ssl.keyStore",         raizMios + "KeyStoreCliente_2017.jce");
	System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
	System.setProperty("javax.net.ssl.keyStorePassword", "123456");

	// Almacen de confianza
	System.setProperty("javax.net.ssl.trustStore",          raizMios + "TrustStoreCliente_2017.jce");
	
	System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
	System.setProperty("javax.net.ssl.trustStorePassword", "123456");

}

private static void definirKeyStoresCliente()
{
    
	// ----  Almacenes mios  -----------------------------
	
	// Almacen de claves
	
	System.setProperty("javax.net.ssl.keyStore",         raizMios + "KeyStoreCliente_2017.jce");
	System.setProperty("javax.net.ssl.keyStoreType",     "JCEKS");
	System.setProperty("javax.net.ssl.keyStorePassword", "123456");

	// Almacen de confianza
  
	System.setProperty("javax.net.ssl.trustStore",          raizMios + "TrustStoreCliente_2017.jce");
	System.setProperty("javax.net.ssl.trustStoreType",     "JCEKS");
	System.setProperty("javax.net.ssl.trustStorePassword", "123456");
  
	// Almacen de credenciales
	
	//System.setProperty("javax.net.ssl.keyStore",         raiz + "testkeys.jks");
	//System.setProperty("javax.net.ssl.keyStoreType",     "JKS");
    //System.setProperty("javax.net.ssl.keyStorePassword", "passphrase");

    // Almacen de confianza
  
    // System.setProperty("javax.net.ssl.trustStore",          raiz + "samplecacerts.jks");
	//System.setProperty("javax.net.ssl.trustStoreType",     "JKS");
	//System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
  

    // Almacen de confianza del sistema
	  
    //System.setProperty("javax.net.ssl.trustStore",          "C:/Program Files/Java/jre1.8.0_40/lib/security/cacerts");
	//System.setProperty("javax.net.ssl.trustStoreType",     "JKS");
	//System.setProperty("javax.net.ssl.trustStorePassword", "changeitv");
    
	//C:\Program Files\Java\jre1.8.0_40\lib\security\cacerts


}




public String menu () {
	String select="";	
	System.out.println("Seleccione la operación que desea:\n\n");

	System.out.println("\n 1)Registrar Documento \n 2)Listar Documento \n 3)Recuperar documento");
	
	BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
	
	switch(select) {
	
	
	
	
	}
	
	return select;
	
}


}


