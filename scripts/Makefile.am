EXTRA_DIST		= mib-identifiers.txt

MIBS = RFC1213-MIB \
	SNMPv2-MIB IF-MIB IP-MIB IP-FORWARD-MIB UDP-MIB TCP-MIB \
	SNMP-FRAMEWORK-MIB SNMP-VIEW-BASED-ACM-MIB \
	SNMP-TARGET-MIB SNMP-NOTIFICATION-MIB \
	SNMP-COMMUNITY-MIB SNMP-USER-BASED-SM-MIB \
	HOST-RESOURCES-MIB Printer-MIB \
	ENTITY-MIB \
	EtherLike-MIB MAU-MIB BRIDGE-MIB

mib-identifiers.txt:	
	@for f in "$(MIBS)" ; do \
	    smidump -f identifiers $$f | egrep -v "(group)|(compliance)" >> mib-identifiers.txt
	done
