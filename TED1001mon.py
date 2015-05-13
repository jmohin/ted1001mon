#!/usr/bin/env python

# This is a Python module for The Energy Detective: A low-cost whole
# house energy monitoring system. For more information on TED, see
# http://theenergydetective.com
#
# This module was not created by Energy, Inc. nor is it supported by
# them in any way. It was created using information from two sources:
# David Satterfield's TED module for Misterhouse, and my own reverse
# engineering from examining the serial traffic between TED Footprints
# and my RDU.
#
# I have only tested this module with the model 1001 RDU, with
# firmware version 9.01U. The USB port is uses the very common FTDI
# USB-to-serial chip, so the RDU will show up as a serial device on
# Windows, Mac OS, or Linux.
#
#
# Copyright (c) 2008 Micah Dowty <micah@navi.cx>
#
# NOT copyright Jake Mohin, 2015.  <jmohin@gmail.com>
# 
# I edited Micah Dowty's code to upload to a few web services.  
# She did all the hard work.  I removed the SVN repository
# link because it hasn't been update for a few years.  This code is freely available 
# at my github. The below disclaimers still apply.
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.

import MySQLdb
import serial
import time
from datetime import datetime 
import binascii
import sys
import struct
import urllib
import urllib2
import base64
import os

#print-to-terminal web upload messages or data sent to web
WEB_DEBUG=0
DATA_DEBUG=0
# Special bytes
PKT_REQUEST = "\xAA"
ESCAPE      = "\x10"
PKT_BEGIN   = "\x04"
PKT_END     = "\x03"
# Web upload parameters; UPDATE_INT should be min 1 second, Upload freq (which is UPDATE_INT*DATA_PTS) should be min 60 seconds
DATA_PTS    = 60
UPDATE_INT  = 1 #seconds
#Bidgely
HOST        = "http://api.bidgely.com"
API_URL     = "v1/users/270b741a-a3d4-4f4b-82d0-34ff9ac4fbbb/homes/1/gateways/7/upload"
#PlotWatt
METER_ID="1018143"
API_KEY="ZWNlZDhmODIxMWU5"
URL="http://plotwatt.com/api/v2/push_readings"
#WattVision
_WV_ELEC_URL_  = "http://www.wattvision.com/api/v0.2/elec/"
_WV_API_ID_  = 'cstyf3y5slre919lb3h1mv7v6cgxfm4z'
_WV_API_KEY_ = 'inhx1r6qwau2vonc0yfrxgthvwvtdol6'
_SENSOR_ID_  = '20659802'
#Phant online sensor database
# server="http://data.sparkfun.com/input/"
server='http://localhost:8080/input/'
publicKey='zVMEg0Ne2LhZwNEX66NPcKkPE922'
privateKey='55XOzAwN2KcXZ4NDLL42cOpg8jAA'
#CSV file 
CSV_PATH = '/opt/powerData/'
CSV_PREFIX = 'powerDat'
# Mysql parameters
DBHOST  = "localhost"
DBUSER  = "sensor_user"
DBPASS  = "jake"

class ProtocolError(Exception):
    pass

class TED(object):
    def __init__(self, device):
        self.port = serial.Serial(device, 19200, timeout=0)
        self.escape_flag = False

        # None indicates that the packet buffer is invalid:
        # we are not receiving any valid packet at the moment.
        self.packet_buffer = None

    def poll(self):
        """Request a packet from the RDU, and flush the operating
           system's receive buffer. Any complete packets we've
           received will be decoded. Returns a list of Packet
           instances.

           Raises ProtocolError if we see anything from the RDU that
           we don't expect.
           """

        # Request a packet. The RDU will ignore this request if no
        # data is available, and there doesn't seem to be any harm in
        # sending the request more frequently than once per second.
        self.port.write(PKT_REQUEST)

        return self.decode(self.port.read(4096))

    def decode(self, raw):
        """Decode some raw data from the RDU. Updates internal
           state, and returns a list of any valid Packet() instances
           we were able to extract from the raw data stream.
           """

        packets = []

        # The raw data from the RDU is framed and escaped. The byte
        # 0x10 is the escape byte: It takes on different meanings,
        # depending on the byte that follows it. These are the
        # escape sequence I know about:
        #
        #    10 10: Encodes a literal 0x10 byte.
        #    10 04: Beginning of packet
        #    10 03: End of packet
        #
        # This code illustrates the most straightforward way to
        # decode the packets. It's best in a low-level language like C
        # or Assembly. In Python we'd get better performance by using
        # string operations like split() or replace()- but that would
        # make this code much harder to understand.

        for byte in raw:
            if self.escape_flag:
                self.escape_flag = False
                if byte == ESCAPE:
                    if self.packet_buffer is not None:
                        self.packet_buffer += ESCAPE
                elif byte == PKT_BEGIN:
                    self.packet_buffer = ''
                elif byte == PKT_END:
                    if self.packet_buffer is not None:
                        packets.append(Packet(self.packet_buffer))
                        self.packet_buffer = None
                else:
                    raise ProtocolError("Unknown escape byte %r" % byte)

            elif byte == ESCAPE:
                self.escape_flag = True
            elif self.packet_buffer is not None:
                self.packet_buffer += byte

        return packets

class Packet(object):
    """Decoder for TED packets. We use a lookup table to find individual
       fields in the packet, convert them using the 'struct' module,
       and scale them. The results are available in the 'fields'
       dictionary, or as attributes of this object.
       """
    
    # We only support one packet length. Any other is a protocol error.
    _protocol_len = 278

    _protocol_table = (
        # TODO: Fill in the rest of this table.
        #
        # It needs verification on my firmware version, but so far the
        # offsets in David Satterfield's code match mine. Since his
        # code does not handle packet framing, his offsets are 2 bytes
        # higher than mine. These offsets start counting at the
        # beginning of the packet body. Packet start and packet end
        # codes are omitted.

        # Offset,  name,             fmt,     scale
        (82,       'kw_rate',        "<H",    0.0001),
        (247,      'KwNowDsp',       "<H",    0.01),
        (249,      'DlrNowDsp',      "<H",    0.01),
        (251,      'VrmsNowDsp',     "<H",    0.1),
        (253,      'DlrMtdDsp',      "<H",    0.1),
        (255,      'DlrMthProjDsp',  "<H",    0.1),
        (257,      'KwhMthProjDsp',  "<H",    1),
        (132,      'LoVrmsTdy',      "<H",    0.1),
        (136,      'HiVrmsTdy',      "<H",    0.1),
        (140,      'LoVrmsMtd',      "<H",    0.1),
        (143,      'HiVrmsMtd',      "<H",    0.1),
        (146,      'KwPeakTdy',      "<H",    0.01),
        (148,      'DlrPeakTdy',     "<H",    0.01),
        (150,      'KwPeakMtd',      "<H",    0.01),
        (152,      'DlrPeakMtd',     "<H",    0.01),        
        (154,      'DlrTdySum',      "<L",    0.00000167),
        (158,      'KWhrTdySum',     "<L",    0.0000167),
        (166,      'KWhrMtdSum',     "<L",    0.0000167),
        (170,      'DlrMtdSum',      "<L",    0.00000167),
        )

    def __init__(self, data):
        self.data = data
        self.fields = {}
        if len(data) != self._protocol_len:
            raise ProtocolError("Unsupported packet length %r" % len(data))

        for offset, name, fmt, scale in self._protocol_table:
            size = struct.calcsize(fmt)
            field = data[offset:offset+size]
            value = struct.unpack(fmt, field)[0] * scale

            setattr(self, name, value)
            self.fields[name] = value

def do_upload_bidgely(xml_data):
    if(DATA_DEBUG):
        print xml_data

    request_body_encoded = xml_data.encode('utf-8')
    request  = urllib2.Request( url=(HOST+'/'+API_URL), data=xml_data , headers={'Content-Type': 'application/xml'})
    try:    
        response = urllib2.urlopen( request )
    except urllib2.URLError, e:
        print "bidgely error:"
        print e.reason

    # return response

def make_xml_bidgely(kW_data):
	xmlHead="""<upload version="1.0">
	<meters>
	<meter id=\"11:22:33:44:55:66" model="TED1001" type="0" description="TED1001 whole home device">
		<streams>
			<stream id="InstantaneousDemand" unit="kW" description="Real-Time Demand">"""

	xmlDline="<data time=\"%(time)s\" value=\"%(kW)s\" />"

	xmlTail="""</stream>
		</streams>
		<attributes>
		</attributes>
		<messages>
		</messages>
	</meter>
	</meters>
	<attributes> 
		<attribute id="LocalIP">192.168.1.101</attribute>
	    </attributes>
	<messages> 
	</messages> 
	</upload>"""

	xmlFin=xmlHead

	for i in range(len(kW_data)):
		tmpDat={'time':kW_data[i][0],'kW':kW_data[i][1]}
		xmlFin = xmlFin + (xmlDline % tmpDat)

	xmlFin = str(xmlFin + xmlTail)	
	return  xmlFin

def writeToCSV(data):
	
	st = datetime.fromtimestamp(time.time()).strftime('%m-%d-%y')
	fnam=CSV_PATH + CSV_PREFIX + st + ".csv"
	if not os.path.exists(fnam):
		nf=open(fnam,'w')
		nf.write("UTC Epoch, kW, Volts\n")
		nf.close()
	
	f = open(fnam,"a")
	for i in range(len(data)): 
		f.write("%s, %s ,%s\n" % (data[i][0],data[i][1],data[i][2]))
		
	f.close()

def do_upload_plotWatt(kW_data):
    dUp="%(Mid)s, %(kW)s, %(time)s, "
    fin=" "
    for i in range(len(kW_data)):
        tmpD={'Mid':METER_ID,'time':kW_data[i][0],'kW':kW_data[i][1]}
        fin = fin + (dUp % tmpD)
    fin=fin[1:-2]

    if(DATA_DEBUG):
        print fin

    base64string = base64.encodestring('%s:%s' % (API_KEY, ''))[:-1]
    authheader =  "Basic %s" % base64string
    req = urllib2.Request(URL)
    req.add_header("Authorization", authheader)
	
    try:    
        response = urllib2.urlopen( req,fin )
    except urllib2.URLError, e:
        print "plotwatt error:"
        print e.reason
    
    #print "PlotWatt: " 
    #print response.getcode()
    #print response.info()


def doUploadWattvision(watts):
    str_fmt = '{{"sensor_id": "{0}", "api_id": "{1}", "api_key": "{2}", "watts": {3} }}'
    request_body = str_fmt.format(str(_SENSOR_ID_),str(_WV_API_ID_),str(_WV_API_KEY_),watts)  
    if (DATA_DEBUG):
        print request_body

    request_body_encoded = request_body.encode('utf-8')
    request  = urllib2.Request( url=_WV_ELEC_URL_, data=request_body_encoded )
    try:    
        response = urllib2.urlopen( request )
    except urllib2.URLError, e:
        print "wattvision error:"
        print e.reason
        return e

    # if(WEB_DEBUG):
    #     print "Wattvision: " 
    #     print response.getcode()
    #     print response.info()

    return response

def doUploadPhant(d1,d2):
 
    fields = ["kw","volts"] # Your feed's data fields
    data = {} 
    data[fields[0]] = d1
    data[fields[1]] = d2
    params = urllib.urlencode(data)

    request  = urllib2.Request( url=server+publicKey, data=params , headers=
        {'Content-Type': 'application/x-www-form-urlencoded',
        'Connection': 'close',
        'Content-Length': len(params),
        'Phant-Private-Key': privateKey
        })
   
    try:    
        response = urllib2.urlopen( request )
    except urllib2.URLError, e:
        print e.reason

    # if(WEB_DEBUG):
    #     print "Phant: " 
    #     print response.getcode()
    #     print response.info()


def printPacket(packet):
    print
    print "%d byte packet: %r" % (
        len(packet.data), binascii.b2a_hex(packet.data))
    print
    for name, value in packet.fields.items():
        print "%s = %s" % (name, value)   


def mySQLsave(dbname,dbtable,fields,fieldspec,datArr):

    #configure MySQL connection for database logging
    db = MySQLdb.connect(host=DBHOST, user=DBUSER, passwd=DBPASS, db=dbname)
    CURSOR = db.cursor()

    sqlString='INSERT INTO '+ dbtable + fields+' VALUES '

    #date field NEEDS TO BE FIRST!

    #CHANGED to every 90 seconds update so as to not pollute the database :-)
    for i in range(len(datArr)):
        ts='("' + str(datetime.utcfromtimestamp(datArr[i][0])) + '",'
        for j in range(1,len(datArr[i])):
            ts=ts+fieldspec[j-1]%datArr[i][j]+','

        sqlString = sqlString+ts[0:-1]+'),'

    sqlString=sqlString[0:-1]
    # print sqlString
    try:
         CURSOR.execute(sqlString)
         db.commit()
    except MySQLdb.Error as e:
         print("MySql Error %d: %s" % (e.args[0], e.args[1]))


def main():
    #instantiate serial packet grabber
    t = TED(sys.argv[1]) 
   
    #configure array and counter for periodic web upload
    count=0
    upCount=0
    powerArr=[[0 for x in xrange(3)] for x in xrange(DATA_PTS)]

    while True:
        for packet in t.poll():
            # printPacket(packet)

            if len(packet.fields.items()[16]):
                if (count)>DATA_PTS-1:
                    count=0
                    print "Caught a count out of bounds"

                powerArr[count][0]=int(round(time.time()))
                powerArr[count][1]=packet.fields.items()[16][1]
                powerArr[count][2]=packet.fields.items()[3][1]
                count+=1

                doUploadWattvision(packet.fields.items()[16][1]*1000) 
                # doUploadPhant(packet.fields.items()[16][1],packet.fields.items()[3][1])
               
            if (count*UPDATE_INT)%DATA_PTS == 0:
        	upCount+=1
        	if count==0:
        		print "cought a 0=count%freq error"
        		continue
        	do_upload_plotWatt(powerArr) 
        	do_upload_bidgely(make_xml_bidgely(powerArr))
                mySQLsave("sensor_data","power_data","(ts,kW,volts)",['%d','%d'],powerArr)
        	print "upload #: %s " % upCount
        	count=0

            time.sleep(UPDATE_INT)

	     			

if __name__ == "__main__":
    main()
