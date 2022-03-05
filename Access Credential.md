### find DC in network:
 ` netstat -ba | Select-String -pattern "ESTABLISHED" -Context 0,1 ` 
 
