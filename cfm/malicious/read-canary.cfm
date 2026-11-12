<cfcontent type="text/plain"><cftry><cfoutput>#fileRead("/tmp/pentest-canary.txt","utf-8")#</cfoutput><cfcatch><cfoutput>pentest: canary unavailable</cfoutput></cfcatch></cftry>
