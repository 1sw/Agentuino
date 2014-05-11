/*
  Agentuino.cpp - An Arduino library for a lightweight SNMP Agent.
  Copyright (C) 2010 Eric C. Gionet <lavco_eg@hotmail.com>
  All rights reserved.

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

//
// sketch_aug23a
//

#include "Agentuino.h"
#include "EthernetUdp.h"

EthernetUDP Udp;
SNMP_API_STAT_CODES AgentuinoClass::begin()
{
	// set community names
	_getCommName = "public";
	_setCommName = "private";
	//
	// set community name set/get sizes
	_setSize = strlen(_setCommName);
	_getSize = strlen(_getCommName);
	//
	// init UDP socket
	Udp.begin(SNMP_DEFAULT_PORT);
	//
	return SNMP_API_STAT_SUCCESS;
}

SNMP_API_STAT_CODES AgentuinoClass::begin(char *getCommName, char *setCommName, uint16_t port)
{
	// set community name set/get sizes
	_setSize = strlen(setCommName);
	_getSize = strlen(getCommName);
	//
	// validate get/set community name sizes
	if ( _setSize > SNMP_MAX_NAME_LEN + 1 || _getSize > SNMP_MAX_NAME_LEN + 1 ) {
		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	// set community names
	_getCommName = getCommName;
	_setCommName = setCommName;
	//
	// validate session port number
	if ( port == NULL || port == 0 ) port = SNMP_DEFAULT_PORT;
	//
	// init UDP socket
	Udp.begin(port);

	return SNMP_API_STAT_SUCCESS;
}

void AgentuinoClass::listen(void)
{
	// if bytes are available in receive buffer
	// and pointer to a function (delegate function)
	// isn't null, trigger the function
	Udp.parsePacket();
	if ( Udp.available() && _callback != NULL ) (*_callback)();
}


SNMP_API_STAT_CODES AgentuinoClass::requestPdu(SNMP_PDU *pdu)
{
	char *community;
	// sequence length
	byte seqLen;
	// version
	byte verLen, verEnd;
	// community string
	byte comLen, comEnd;
	// pdu
	byte pduTyp, pduLen;
	byte ridLen, ridEnd;
	byte errLen, errEnd;
	byte eriLen, eriEnd;
	byte vblTyp, vblLen;
	byte vbiTyp, vbiLen;
	byte obiLen, obiEnd;
	byte valTyp, valLen, valEnd;
	byte i;
	//
	// set packet packet size (skip UDP header)
	_packetSize = Udp.available();
	//
	// reset packet array
	memset(_packet, 0, SNMP_MAX_PACKET_LEN);
	//
	// validate packet
	if ( _packetSize != 0 && _packetSize > SNMP_MAX_PACKET_LEN ) {
		//
		//SNMP_FREE(_packet);

		return SNMP_API_STAT_PACKET_TOO_BIG;
	}
	//
	// get UDP packet
	//Udp.parsePacket();
	Udp.read(_packet, _packetSize);
// 	Udp.readPacket(_packet, _packetSize, _dstIp, &_dstPort);
	//
	// packet check 1
	if ( _packet[0] != 0x30 ) {
		//
		//SNMP_FREE(_packet);

		return SNMP_API_STAT_PACKET_INVALID;
	}
	//
	// sequence length
	seqLen = _packet[1];
	// version
	verLen = _packet[3];
	verEnd = 3 + verLen;
	// community string
	comLen = _packet[verEnd + 2];
	comEnd = verEnd + 2 + comLen;
	// pdu
	pduTyp = _packet[comEnd + 1];
	pduLen = _packet[comEnd + 2];
	ridLen = _packet[comEnd + 4];
	ridEnd = comEnd + 4 + ridLen;
	errLen = _packet[ridEnd + 2];
	errEnd = ridEnd + 2 + errLen;
	eriLen = _packet[errEnd + 2];
	eriEnd = errEnd + 2 + eriLen;
	vblTyp = _packet[eriEnd + 1];
	vblLen = _packet[eriEnd + 2];
	vbiTyp = _packet[eriEnd + 3];
	vbiLen = _packet[eriEnd + 4];
	obiLen = _packet[eriEnd + 6];
	obiEnd = eriEnd + obiLen + 6;
	valTyp = _packet[obiEnd + 1];
	valLen = _packet[obiEnd + 2];
	valEnd = obiEnd + 2 + valLen;
	//
	// extract version
	pdu->version = 0;
	for ( i = 0; i < verLen; i++ ) {
		pdu->version = (pdu->version << 8) | _packet[5 + i];
	}
	//
	// validate version
	//
	// pdu-type
	pdu->type = (SNMP_PDU_TYPES)pduTyp;
	_dstType = pdu->type;
	//
	// validate community size
	if ( comLen > SNMP_MAX_NAME_LEN ) {
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;
		//
		return SNMP_API_STAT_NAME_TOO_BIG;
	}
	//
	//
	// validate community name
	if ( pdu->type == SNMP_PDU_SET && comLen == _setSize ) {
		//
		for ( i = 0; i < _setSize; i++ ) {
			if( _packet[verEnd + 3 + i] != (byte)_setCommName[i] ) {
				// set pdu error
				pdu->error = SNMP_ERR_NO_SUCH_NAME;
				//
				return SNMP_API_STAT_NO_SUCH_NAME;
			}
		}
	} else if ( pdu->type == SNMP_PDU_GET && comLen == _getSize ) {
		//
		for ( i = 0; i < _getSize; i++ ) {
			if( _packet[verEnd + 3 + i] != (byte)_getCommName[i] ) {
				// set pdu error
				pdu->error = SNMP_ERR_NO_SUCH_NAME;
				//
				return SNMP_API_STAT_NO_SUCH_NAME;
			}
		}
	} else if ( pdu->type == SNMP_PDU_GET_NEXT && comLen == _getSize ) {
		//
		for ( i = 0; i < _getSize; i++ ) {
			if( _packet[verEnd + 3 + i] != (byte)_getCommName[i] ) {
				// set pdu error
				pdu->error = SNMP_ERR_NO_SUCH_NAME;
				//
				return SNMP_API_STAT_NO_SUCH_NAME;
			}
		}
	} else {
		// set pdu error
		pdu->error = SNMP_ERR_NO_SUCH_NAME;
		//
		return SNMP_API_STAT_NO_SUCH_NAME;
	}
	//
	//
	// extract reqiest-id 0x00 0x00 0x00 0x01 (4-byte int aka int32)
	pdu->requestId = 0;
	for ( i = 0; i < ridLen; i++ ) {
		pdu->requestId = (pdu->requestId << 8) | _packet[comEnd + 5 + i];
	}
	//
	// extract error 
	pdu->error = SNMP_ERR_NO_ERROR;
	int32_t err = 0;
	for ( i = 0; i < errLen; i++ ) {
		err = (err << 8) | _packet[ridEnd + 3 + i];
	}
	pdu->error = (SNMP_ERR_CODES)err;
	//
	// extract error-index 
	pdu->errorIndex = 0;
	for ( i = 0; i < eriLen; i++ ) {
		pdu->errorIndex = (pdu->errorIndex << 8) | _packet[errEnd + 3 + i];
	}
	//
	//
	// validate object-identifier size
	if ( obiLen > SNMP_MAX_OID_LEN ) {
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;

		return SNMP_API_STAT_OID_TOO_BIG;
	}
	//
	// extract and contruct object-identifier
	memset(pdu->OID.data, 0, SNMP_MAX_OID_LEN);
	pdu->OID.size = obiLen;
	for ( i = 0; i < obiLen; i++ ) {
		pdu->OID.data[i] = _packet[eriEnd + 7 + i];
	}
	//
	// value-type
	pdu->VALUE.syntax = (SNMP_SYNTAXES)valTyp;
	//
	// validate value size
	if ( obiLen > SNMP_MAX_VALUE_LEN ) {
		// set pdu error
		pdu->error = SNMP_ERR_TOO_BIG;

		return SNMP_API_STAT_VALUE_TOO_BIG;
	}
	//
	// value-size
	pdu->VALUE.size = valLen;
	//
	// extract value
	memset(pdu->VALUE.data, 0, SNMP_MAX_VALUE_LEN);
	for ( i = 0; i < valLen; i++ ) {
		pdu->VALUE.data[i] = _packet[obiEnd + 3 + i];
	}
	//
	return SNMP_API_STAT_SUCCESS;
}

SNMP_API_STAT_CODES AgentuinoClass::responsePdu(SNMP_PDU *pdu)
{
	int32_u u;
	byte i;
	//
	// Length of entire SNMP packet
	_packetPos = 0;  // 23
	_packetSize = 25 + sizeof(pdu->requestId) + sizeof(pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size;
	//
	memset(_packet, 0, SNMP_MAX_PACKET_LEN);
	//
	if ( _dstType == SNMP_PDU_SET ) {
		_packetSize += _setSize;
	} else {
		_packetSize += _getSize;
	}
	//
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)_packetSize - 2;		// length
	//
	// SNMP version
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = 0x01;			// length
	_packet[_packetPos++] = 0x00;			// value
	//
	// SNMP community string
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_OCTETS;	// type
	if ( _dstType == SNMP_PDU_SET ) {
		_packet[_packetPos++] = (byte)_setSize;	// length
		for ( i = 0; i < _setSize; i++ ) {
			_packet[_packetPos++] = (byte)_setCommName[i];
		}
	} else {
		_packet[_packetPos++] = (byte)_getSize;	// length
		for ( i = 0; i < _getSize; i++ ) {
			_packet[_packetPos++] = (byte)_getCommName[i];
		}
	}
	//
	// SNMP PDU
	_packet[_packetPos++] = (byte)pdu->type;
	_packet[_packetPos++] = (byte)( sizeof(pdu->requestId) + sizeof((int32_t)pdu->error) + sizeof(pdu->errorIndex) + pdu->OID.size + pdu->VALUE.size + 14 );
	//
	// Request ID (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->requestId);
	u.int32 = pdu->requestId;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof((int32_t)pdu->error);
	u.int32 = pdu->error;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Error Index (size always 4 e.g. 4-byte int)
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_INT;	// type
	_packet[_packetPos++] = (byte)sizeof(pdu->errorIndex);
	u.int32 = pdu->errorIndex;
	_packet[_packetPos++] = u.data[3];
	_packet[_packetPos++] = u.data[2];
	_packet[_packetPos++] = u.data[1];
	_packet[_packetPos++] = u.data[0];
	//
	// Varbind List
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)( pdu->OID.size + pdu->VALUE.size + 6 ); //4
	//
	// Varbind
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_SEQUENCE;	// type
	_packet[_packetPos++] = (byte)( pdu->OID.size + pdu->VALUE.size + 4 ); //2
	//
	// ObjectIdentifier
	_packet[_packetPos++] = (byte)SNMP_SYNTAX_OID;	// type
	_packet[_packetPos++] = (byte)(pdu->OID.size);
	for ( i = 0; i < pdu->OID.size; i++ ) {
		_packet[_packetPos++] = pdu->OID.data[i];
	}
	//
	// Value
	_packet[_packetPos++] = (byte)pdu->VALUE.syntax;	// type
	_packet[_packetPos++] = (byte)(pdu->VALUE.size);
	for ( i = 0; i < pdu->VALUE.size; i++ ) {
		_packet[_packetPos++] = pdu->VALUE.data[i];
	}
	//
	Udp.beginPacket(Udp.remoteIP(), Udp.remotePort());
	Udp.write(_packet, _packetSize);
	Udp.endPacket();
//	Udp.write(_packet, _packetSize, _dstIp, _dstPort);
	//
	return SNMP_API_STAT_SUCCESS;
}



void AgentuinoClass::onPduReceive(onPduReceiveCallback pduReceived)
{
	_callback = pduReceived;
}

void AgentuinoClass::freePdu(SNMP_PDU *pdu)
{
	//
	memset(pdu->OID.data, 0, SNMP_MAX_OID_LEN);
	memset(pdu->VALUE.data, 0, SNMP_MAX_VALUE_LEN);
	free((char *) pdu);
}

// Create one global object
AgentuinoClass Agentuino;