@echo off
rem generate HTML index from Eclipse Table of Content file
rem before using the script, make sure that the transform (any xsl transform command) and sed commands are accessible

java -classpath ../lib/xalan-2.7.0.jar;../lib/xercesImpl-2.8.1.jar;../lib/xml-apis-1.3.04.jar org.apache.xalan.xslt.Process -HTML -IN toc.xml -XSL eclipse.xsl -OUT temp.htm


sed.exe -f eclipse.sed temp.htm > content.htm
del temp.htm
