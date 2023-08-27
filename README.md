# installcert
fork of http://s-n-ushakov.blogspot.com/2013/11/yet-another-installcert-for-java-now.html to use as a library

[![Maven Central](https://maven-badges.herokuapp.com/maven-central/com.github.spyhunter99/install-cert/badge.svg)](https://maven-badges.herokuapp.com/maven-central/com.github.spyhunter99/install-cert)

## History

Aug 2023 - Minor updates to make including new protocol handlers easier and to make all dependencies optional (provided maven scope). 
See `usn.net.ssl.util.Starttls#register(port, classname)` where classname must implement `usn.net.ssl.util.StarttlsHandler`.

Aug 2017 - My original use case was for building a Java installer and making things as painless as possible for the person doing the install.
In this particular case, integration with ldaps was required, which requires the trust chain to be added to the JDK/JRE trust store.
In order to spare the users the pain of doing this manually, I wanted to automated setup whereby the user can just specify the server
ip/host and port number and then be prompted to accept the whole trust chain painlessly.

After searching, I found this post on SO https://stackoverflow.com/a/20280562/1203182. Great post, which linked to here: 
http://s-n-ushakov.blogspot.com/2013/11/yet-another-installcert-for-java-now.html which had binaries and source.

After checking out the code, it had lots of `System.exit(0)` and was clearly not designed to be reused while embedded 
into another application as a utility. That's where this fork comes in. Although very little new functionality has been
added, it has been refactored and reworked to be used as an embedded library.


This is published to maven central.

## What protocols are supported?

 - HTTPS and TLS
 - LDAPS
 - Most email based protocols using SSL/TLS, IMAP, SMTP, POP3
 - Postgres with SSL

## Usage from the command line

This tool can be ran from the command line just like the original version

`> java -jar install-cert-<VERSION>-jar-with-dependencies.jar`

This will display help and usage information.

````
	usage: java -jar install-cert-<VERSION>-jar-with-dependencies.jar
	 -file                    if specified, untrusted certificates will be
							  stored to individial .crt files
	 -host <arg>              The host:port of the server to pull a ssl cert
							  chain from. If not specified, 443 will be used.
	 -noimport                if specified, no changes will be made to trust
							  stores
	 -password <arg>          if specified, your value will be used for the
							  trust store password. if not specified the
							  default jre password will be used
	 -passwordExtra <arg>     if specified, password for the extra trust store
	 -truststore <arg>        if specified, this trust store will be used,
							  otherwise JAVA_HOME/cacerts will be used
	 -truststoreExtra <arg>   if specified, this trust store will also be used
````

### Examples (command line again)

Import to Java JRE/JDK trust store (probably needs to be ran as root/elevated

	`> java -jar install-cert-<VERSION>-jar-with-dependencies.jar -host server:port`
	
Get the certs and store to a file but don't modify any files trust stores

	`> java -jar install-cert-<VERSION>-jar-with-dependencies.jar -host server:port -noimport -file`
	
Imports the certs to a specified trust store

	`> java -jar install-cert-<VERSION>-jar-with-dependencies.jar -host server:port -truststore path/to/trust.jks -password mysecret
	
Import the certs to a primary and secondary store at the same time

	`> java -jar install-cert-<VERSION>-jar-with-dependencies.jar -host server:port -truststore path/to/trust.jks -password mysecret  -truststoreExtra path/to/trust2.jks -passwordExtra mysecret
	
Import the certs to the JRE/JDK trust store and a secondary trust store

	`> java -jar install-cert-<VERSION>-jar-with-dependencies.jar -host server:port -truststoreExtra path/to/trust2.jks -passwordExtra mysecret


Windows users: If the `-truststore` option is not given, then this application will modify the current Java install's trusted root certificate store. This is not normally writable
so it must be ran with an elevated command prompt/power shell/etc. This is usually done via Start > just type `cmd` then right click `Command Prompt`, then `Run as Administrator`

Mac/Linux users: : If the `-truststore` option is not given, then this application will modify the current Java install's trusted root certificate store. This is not normally writable
so it must be as a super user account via su or sudo


## Using this embedded in your application

### Add the dependency

```xml
	<dependency>
		<groupId>com.github.spyhunter99</groupId>
		<artifactId>install-cert</artifactId>
		<version>1.0.4</version>
	</dependency>
```

### Add the code

```java
	usn.net.ssl.util.InstallCert installer = new usn.net.ssl.util.InstallCert();
	//optional installer.setTrustStore(File f, char[] pwd);
	//optional installer.setExtraTrustStore(File f, char[] pwd);
	
	//get the certs
	Set<X509Certificate> untrustedCerts = installer.getCerts(host, port);
	//if this set is not empty, then we found some untrusted certs and where able to connect successfully
	//if it is empty, the connection was successful and no ssl/tls errors occured (already trusted)
	//if an exception is thrown, it's usually a connection or firewall problem.
	//note: this is a potentially long running operation
	
	//this is a great point to prompt the user to trust the certs or not
	//TODO prompt the user for accept/reject the certs
	
	//apply the changes with your user selected certs
	installer.applyChanges(untrustedCerts, host);
	
	//close out the installer, this releases all file handles and clears any specified passwords to the NUL character.
	installer.close();
```









