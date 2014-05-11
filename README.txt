An updated version of the Agentuino (http://code.google.com/p/agentuino/) SNMP library.

The software now support SNMP GET-NEXT-Request



Net-Snmp Get-Next-Request examples
----------------------------------

snmpgetnext -v 1 -c public 192.168.20.6 sysUpTime.0

Output: 
SNMPv2-MIB::sysContact.0 = STRING: Petr Domorazek

snmpwalk -v 1 -c public 192.168.20.6

Output:
SNMPv2-MIB::sysDescr.0 = STRING: Agentuino, a light-weight SNMP Agent.
DISMAN-EVENT-MIB::sysUpTimeInstance = Timeticks: (53100) 0:08:51.00
SNMPv2-MIB::sysContact.0 = STRING: Petr Domorazek
SNMPv2-MIB::sysName.0 = STRING: Agentuino
SNMPv2-MIB::sysLocation.0 = STRING: Czech Republic
SNMPv2-MIB::sysServices.0 = INTEGER: 6
End of MIB