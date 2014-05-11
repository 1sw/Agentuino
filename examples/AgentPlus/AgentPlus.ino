/**
* Agentuino SNMP Agent Library Prototyping...
*
* Copyright 2010 Eric C. Gionet <lavco_eg@hotmail.com>
*
* Update snmpGetNext by Petr Domorazek <petr@domorazek.cz>
*/
#include <Streaming.h>         // Include the Streaming library
#include <Ethernet.h>          // Include the Ethernet library
#include <SPI.h>
#include <MemoryFree.h>
#include <Agentuino.h> 
#include <Flash.h>

static byte mac[] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED };
static byte ip[] = { 192, 168, 20, 6 };
//static byte gateway[] = { 192, 168, 20, 1 };
//static byte subnet[] = { 255, 255, 255, 0 };

//
// tkmib - linux mib browser
//
// RFC1213-MIB OIDs
// .iso (.1)
// .iso.org (.1.3)
// .iso.org.dod (.1.3.6)
// .iso.org.dod.internet (.1.3.6.1)
// .iso.org.dod.internet.mgmt (.1.3.6.1.2)
// .iso.org.dod.internet.mgmt.mib-2 (.1.3.6.1.2.1)
// .iso.org.dod.internet.mgmt.mib-2.system (.1.3.6.1.2.1.1)
// .iso.org.dod.internet.mgmt.mib-2.system.sysDescr (.1.3.6.1.2.1.1.1)
static char sysDescr[] PROGMEM      = "1.3.6.1.2.1.1.1.0";  // read-only  (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysObjectID (.1.3.6.1.2.1.1.2)
//static char sysObjectID[] PROGMEM   = "1.3.6.1.2.1.1.2.0";  // read-only  (ObjectIdentifier)
// .iso.org.dod.internet.mgmt.mib-2.system.sysUpTime (.1.3.6.1.2.1.1.3)
static char sysUpTime[] PROGMEM     = "1.3.6.1.2.1.1.3.0";  // read-only  (TimeTicks)
// .iso.org.dod.internet.mgmt.mib-2.system.sysContact (.1.3.6.1.2.1.1.4)
static char sysContact[] PROGMEM    = "1.3.6.1.2.1.1.4.0";  // read-write (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysName (.1.3.6.1.2.1.1.5)
static char sysName[] PROGMEM       = "1.3.6.1.2.1.1.5.0";  // read-write (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysLocation (.1.3.6.1.2.1.1.6)
static char sysLocation[] PROGMEM   = "1.3.6.1.2.1.1.6.0";  // read-write (DisplayString)
// .iso.org.dod.internet.mgmt.mib-2.system.sysServices (.1.3.6.1.2.1.1.7)
static char sysServices[] PROGMEM   = "1.3.6.1.2.1.1.7.0";  // read-only  (Integer)
//
// Arduino defined OIDs
// .iso.org.dod.internet.private (.1.3.6.1.4)
// .iso.org.dod.internet.private.enterprises (.1.3.6.1.4.1)
// .iso.org.dod.internet.private.enterprises.arduino (.1.3.6.1.4.1.36582)
//
//
// RFC1213 local values
static char locDescr[]              = "Agentuino, a light-weight SNMP Agent.";  // read-only (static)
//static char locObjectID[]         = "1.3.6.1.3.2009.0";                       // read-only (static)
static uint32_t locUpTime           = 0;                                        // read-only (static)
static char locContact[20]          = "Petr Domorazek";                         // should be stored/read from EEPROM - read/write (not done for simplicity)
static char locName[20]             = "Agentuino";                              // should be stored/read from EEPROM - read/write (not done for simplicity)
static char locLocation[20]         = "Czech Republic";                         // should be stored/read from EEPROM - read/write (not done for simplicity)
static int32_t locServices          = 6;                                        // read-only (static)

uint32_t prevMillis = millis();
char oid[SNMP_MAX_OID_LEN];
SNMP_API_STAT_CODES api_status;
SNMP_ERR_CODES status;

void pduReceived()
{
  SNMP_PDU pdu;
  api_status = Agentuino.requestPdu(&pdu);
  //
  if ((pdu.type == SNMP_PDU_GET || pdu.type == SNMP_PDU_GET_NEXT || pdu.type == SNMP_PDU_SET)
    && pdu.error == SNMP_ERR_NO_ERROR && api_status == SNMP_API_STAT_SUCCESS ) {
    //
    pdu.OID.toString(oid);
    // Implementation SNMP GET NEXT
    if ( pdu.type == SNMP_PDU_GET_NEXT ) {
      char tmpOIDfs[SNMP_MAX_OID_LEN];
      if ( strcmp_P( oid, sysDescr ) == 0 ) {  
        strcpy_P ( oid, sysUpTime ); 
        strcpy_P ( tmpOIDfs, sysUpTime );        
        pdu.OID.fromString(tmpOIDfs);  
      } else if ( strcmp_P(oid, sysUpTime ) == 0 ) {  
        strcpy_P ( oid, sysContact );  
        strcpy_P ( tmpOIDfs, sysContact );        
        pdu.OID.fromString(tmpOIDfs);          
      } else if ( strcmp_P(oid, sysContact ) == 0 ) {  
        strcpy_P ( oid, sysName );  
        strcpy_P ( tmpOIDfs, sysName );        
        pdu.OID.fromString(tmpOIDfs);                  
      } else if ( strcmp_P(oid, sysName ) == 0 ) {  
        strcpy_P ( oid, sysLocation );  
        strcpy_P ( tmpOIDfs, sysLocation );        
        pdu.OID.fromString(tmpOIDfs);                  
      } else if ( strcmp_P(oid, sysLocation ) == 0 ) {  
        strcpy_P ( oid, sysServices );  
        strcpy_P ( tmpOIDfs, sysServices );        
        pdu.OID.fromString(tmpOIDfs);                  
      } else if ( strcmp_P(oid, sysServices ) == 0 ) {  
        strcpy_P ( oid, "1.0" );  
      } else {
          int ilen = strlen(oid);
          if ( strncmp_P(oid, sysDescr, ilen ) == 0 ) {
            strcpy_P ( oid, sysDescr ); 
            strcpy_P ( tmpOIDfs, sysDescr );        
            pdu.OID.fromString(tmpOIDfs); 
          } else if ( strncmp_P(oid, sysUpTime, ilen ) == 0 ) {
            strcpy_P ( oid, sysUpTime ); 
            strcpy_P ( tmpOIDfs, sysUpTime );        
            pdu.OID.fromString(tmpOIDfs); 
          } else if ( strncmp_P(oid, sysContact, ilen ) == 0 ) {
            strcpy_P ( oid, sysContact ); 
            strcpy_P ( tmpOIDfs, sysContact );        
            pdu.OID.fromString(tmpOIDfs); 
          } else if ( strncmp_P(oid, sysName, ilen ) == 0 ) {
            strcpy_P ( oid, sysName ); 
            strcpy_P ( tmpOIDfs, sysName );        
            pdu.OID.fromString(tmpOIDfs);   
          } else if ( strncmp_P(oid, sysLocation, ilen ) == 0 ) {
            strcpy_P ( oid, sysLocation ); 
            strcpy_P ( tmpOIDfs, sysLocation );        
            pdu.OID.fromString(tmpOIDfs);    
            } else if ( strncmp_P(oid, sysServices, ilen ) == 0 ) {
            strcpy_P ( oid, sysServices ); 
            strcpy_P ( tmpOIDfs, sysServices );        
            pdu.OID.fromString(tmpOIDfs);  
            }            
      } 
    }
    // End of implementation SNMP GET NEXT / WALK
    
    if ( strcmp_P(oid, sysDescr ) == 0 ) {
      // handle sysDescr (set/get) requests
      if ( pdu.type == SNMP_PDU_SET ) {
        // response packet from set-request - object is read-only
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = SNMP_ERR_READ_ONLY;
      } else {
        // response packet from get-request - locDescr
        status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locDescr);
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      }
      //
    } else if ( strcmp_P(oid, sysUpTime ) == 0 ) {
      // handle sysName (set/get) requests
      if ( pdu.type == SNMP_PDU_SET ) {
        // response packet from set-request - object is read-only
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = SNMP_ERR_READ_ONLY;
      } else {
        // response packet from get-request - locUpTime
        status = pdu.VALUE.encode(SNMP_SYNTAX_TIME_TICKS, locUpTime);       
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      }
      //
    } else if ( strcmp_P(oid, sysName ) == 0 ) {
      // handle sysName (set/get) requests
      if ( pdu.type == SNMP_PDU_SET ) {
        // response packet from set-request - object is read/write
        status = pdu.VALUE.decode(locName, strlen(locName)); 
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      } else {
        // response packet from get-request - locName
        status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locName);
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      }
      //
    } else if ( strcmp_P(oid, sysContact ) == 0 ) {
      // handle sysContact (set/get) requests
      if ( pdu.type == SNMP_PDU_SET ) {
        // response packet from set-request - object is read/write
        status = pdu.VALUE.decode(locContact, strlen(locContact)); 
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      } else {
        // response packet from get-request - locContact
        status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locContact);
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      }
      //
    } else if ( strcmp_P(oid, sysLocation ) == 0 ) {
      // handle sysLocation (set/get) requests
      if ( pdu.type == SNMP_PDU_SET ) {
        // response packet from set-request - object is read/write
        status = pdu.VALUE.decode(locLocation, strlen(locLocation)); 
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      } else {
        // response packet from get-request - locLocation
        status = pdu.VALUE.encode(SNMP_SYNTAX_OCTETS, locLocation);
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      }
      //
    } else if ( strcmp_P(oid, sysServices) == 0 ) {
      // handle sysServices (set/get) requests
      if ( pdu.type == SNMP_PDU_SET ) {
        // response packet from set-request - object is read-only
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = SNMP_ERR_READ_ONLY;
      } else {
        // response packet from get-request - locServices
        status = pdu.VALUE.encode(SNMP_SYNTAX_INT, locServices);
        pdu.type = SNMP_PDU_RESPONSE;
        pdu.error = status;
      }
      //
    } else {
      // oid does not exist
      // response packet - object not found
      pdu.type = SNMP_PDU_RESPONSE;
      pdu.error = SNMP_ERR_NO_SUCH_NAME;
    }
    //
    Agentuino.responsePdu(&pdu);
  }
  //
  Agentuino.freePdu(&pdu);
  //
}

void setup()
{
  //Serial.begin(9600);
  Ethernet.begin(mac, ip);
  //
  api_status = Agentuino.begin();
  //
  if ( api_status == SNMP_API_STAT_SUCCESS ) {
    //
    Agentuino.onPduReceive(pduReceived);
    //
    delay(10);
    //
    return;
  }
  //
  delay(10);
}

void loop()
{
  // listen/handle for incoming SNMP requests
  Agentuino.listen();
  //
  // sysUpTime - The time (in hundredths of a second) since
  // the network management portion of the system was last
  // re-initialized.
  if ( millis() - prevMillis > 1000 ) {
    // increment previous milliseconds
    prevMillis += 1000;
    //
    // increment up-time counter
    locUpTime += 100;
  }
}
