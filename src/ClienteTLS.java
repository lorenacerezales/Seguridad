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

private static String 	raizMios     = "C:\\Users\\lorev\\Desktop\\seg"; 

public static void main(String[] args) throws Exception {
 
 String 	host 				= null;
 int 		port 				= -1;
 String 	path 				= null;
 char[] 	contraseña 		  	= "123456".toCharArray();
 char[] 	contraseñaEntrada 	= "123456".toCharArray();
 String[]   cipherSuites = null;//CipherSuites se va a utilizar para guardar la informacion sobre los algoritmos utilizados en la conexión SSL
	    
 
 definirKeyStoresMios();//EIIIIIIIIIIII
 //PEPE

 for (int i = 0; i < args.length; i++)
     System.out.println(args[i]);
//Deben introducirse 3 entradas por linea de comando (host,port,path)
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
     SSLSocketFactory factory = null;//Socket

     SSLContext 		ctx;// Para la implementacion de un socket seguro
     KeyManagerFactory 	kmf;//Esta clase funciona como una fábrica de claves seguras
     KeyStore 			ks;//Para almacenar claves criptográficas y CERTIFICADOS

     try {
	
	         ctx = SSLContext.getInstance("TLS"); //Devuelve un contexto SSL que utilice el protocolo TLS  

	         // Definir el/los KeyManager.
	         //    Ahora son necesarios ya que el cliente necesita autenticarnse
	         //    y por tanto al SSL tenemos que informarle de donde tomar las
	         //    credenciales del cliente.
	         //
	         kmf = KeyManagerFactory.getInstance("SunX509");//"SunX509" se refiere al proveedor de JSSE Java puro de Oracle America
	         ks = KeyStore.getInstance("JCEKS");//Estamos proporcionando un tipo de almacén de claves específico,en este caso en el almacén
	                                            //proporcionado por el proveedor de SunJCE.
			 ks.load(new FileInputStream(raizMios + "KeyStoreCliente_2017.jce"), contraseña);
			 /*Se proporciona una clave para poder desbloquear el almacén, y un directorio de almacenamiento de esas claves(AUN NO SE DONDE
			  * CONSEGUIR ESE JCE*/
			                                           
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
 	   	     /*Devuelve los nombres de las suites de cifrado que podrían habilitarse para su uso en una conexión SSL. Normalmente, 
 	   	      * solo un subconjunto de estos se habilitará de manera predeterminada, ya que esta lista puede
 	   	      *  incluir conjuntos de cifrado que no cumplen con los requisitos de calidad de servicio para esos valores predeterminados. 
 	   	      */
 	   	     for (int i=0; i<cipherSuites.length; i++) 
 	       		System.out.println (cipherSuites[i]);	    
 		   	    
 	   	     // Suites habilitadas por defecto
 	
 	   	     System.out.println ("****** CypherSuites Habilitadas por defecto **********");
 	   	    
 	   	     String[] cipherSuitesDef = factory.getDefaultCipherSuites();
 	   	     /*Devuelve la lista de suites de cifrado que están habilitadas de forma predeterminada. A menos que se habilite una lista diferente,
 	   	     el protocolo de enlace en una conexión SSL utilizará uno de estos conjuntos de cifrado.*/
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
     
     
 
 	    /* (SSL_TipoNegClave_[EXPORT]_WITH_AlgCifrado_AlgHash_PRF)--->este es el formato utilizado
 	   
 	  
 	    o AlgCifrado: Algoritmo de cifrado a usar por el Protocolo Record.
 	          o Si cifrado en bloque: NombreAlgoritmo_ modotrabajo
 	          o Si cifrado en Flujo: NombreAlgoritmo_LongitudClave
 	   */
     String[]   cipherSuitesHabilitadas = {"TLS_RSA_WITH_AES_128_CBC_SHA"};//(128-->LONGITUD CLAVE)
     			/*CipherSuites se va a utilizar para especificar (es como una variable que guarda los algoritmos que se utilizan):
     			 *  un algoritmo de intercambio de claves,
     			 *  un algoritmo de cifrado masivo y
     			 *  un algoritmo de código de autenticación de mensajes (MAC)
     			 * 							
     			 */
     
	 //cipherSuitesHabilitadas[0] = cipherSuites[0];

	 System.out.println (cipherSuitesHabilitadas[0]);
	 
     
	 socket.setEnabledCipherSuites(cipherSuitesHabilitadas);//Guardamos ya las suites que queremos nosotros

 	 System.out.println ("****** CypherSuites Habilitadas en el ssl socket **********");

	 String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
 	 for (int i=0; i<cipherSuitesHabilSocket.length; i++) 
	       		System.out.println (cipherSuitesHabilSocket[i]);//Debería devolver lo que acabamos de meter
	 
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
   
    socket.startHandshake();//Iniciamos el protocolo Handshake que es el que lleva a cabo la negociacion entre cliente y servidor
    
    System.out.println ("\n*************************************************************");
    System.out.println ("Fin OK SSL Handshake");
    System.out.println ("\n*************************************************************");
     

     PrintWriter out = new PrintWriter(
                           new BufferedWriter(
                           new OutputStreamWriter(
                           socket.getOutputStream())));//Deberia mostrar los acuerdos de la negociacion
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
	 String 	raizMios     = "C:\\Users\\lorev\\Desktop\\seg"; 

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


