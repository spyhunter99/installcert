# installcert
fork of http://s-n-ushakov.blogspot.com/2013/11/yet-another-installcert-for-java-now.html to use as a library

## History

Aug 2017 - My original use case was for building a Java installer and making things as painless as possible for the person doing the install.
In this particular case, integration with ldaps was required, which requires the trust chain to be added to the JDK/JRE trust store.
To spare the users
After searching, I found this post on SO https://stackoverflow.com/a/20280562/1203182. Great post, which linked to here: 
http://s-n-ushakov.blogspot.com/2013/11/yet-another-installcert-for-java-now.html which had binaries and source.

After checking out the code, it had lots of `System.exit(0)` and was clearly not designed to be reused while embedded 
into another application as a utility. That's where this fork comes in. Although very little new functionality has been
added, it has been refactored and reworked to be used as an embedded library.

This will be published to maven central soon.
