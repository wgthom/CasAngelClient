CasAngelClient 1.0 - April 2011



The CasAngelClient is a small authentication shim that leverages the Angel LMS REST API to
provide 
Single Sign-On for Angel in a Jasig CAS environment.  Implemented as a 
.NET HttpHandler
the CasAngleClient is completely independent of the 
Angel code base and can be deployed in its
own application context or 
along side the Angel deployment.



Dependancies

* Angel LMS running https
* Angel LMS API user configured to run AUTHENTICTION_PASS

Installation
* Copy CasAngelClient directory to an appropriate deployment location (e.g. d:\inetpub\cac
* Create a new virtual directory pointing to the deployment location
* Configure core CAS Client - sample configuration and explanations are in the web.conf file
* Configure CasAngelClient - sample configuration and explanations are in the web.conf file



