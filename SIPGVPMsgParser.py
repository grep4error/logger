from LogParser import LogParser
import re, sys
from datetime import datetime
#from logger import submitter
import logging

class SIPGVPMsgParser(LogParser):
    # static vars

# beggining of a SIP message (first line)
# 2015-08-12 08:20:36.949 DBUG 00000000-00000000 3478952256 09400901 CCPSIPMessageInterceptor.h:588 RM - SIP Message received from [10.51.172.120:58403] (1155): \
# INVITE sip:msml=55c29460000054b3@euw1srv-000-rm.euw1.genprim.com;transport=tcp;dn=8463376;record;tenant-dbid=1;media-service=record SIP/2.0

    pattern_sip_msg_received = re.compile('^.+ RM - SIP Message received from \[(\S+)\] \(\S+\): (.+)$')


# 2015-08-12 08:20:36.950 DBUG 00000000-00000000 3478952256 09400901 CCPSIPMessageInterceptor.h:588 \
# RM - SIP Message sent to [10.51.172.120:5060] (493): SIP/2.0 100 Trying


    pattern_sip_msg_sent = re.compile('^.+ RM - SIP Message sent to \[(\S+)\] \(\S+\): (.+)$')
    # Call-ID: ...
    pattern_sip_call_id = re.compile('Call-ID: (.+)$',re.IGNORECASE)
 
     
    def __init__(self,submitter,tags={}):
        logging.debug("SIPGVPMsgParser __init__")
        LogParser.__init__(self, submitter,tags)
        # buffer
        self.sip_msg = ''
        # dictionary for SIP msg
        self.d_sip_msg = {}
        # bool we are in sip msg
        self.in_sip_msg = 0

        
    def init_sip_message(self,msg=''):
        self.in_sip_msg = 1
        self.sip_msg = msg
        #self.d_sip_msg.clear()
        self.d_sip_msg = self.d_common_tags.copy()
        if(msg[:7] == 'SIP/2.0'):
            self.d_sip_msg['method'] = msg[8:].rstrip()
        else:
            self.d_sip_msg['method'] = (msg.split())[0]        
            
        return
    
    def submit_sip_message(self):
        #print "-- end of SIP msg"
        self.d_sip_msg['message'] = self.sip_msg
        self.submitter.d_submit(self.d_sip_msg,"SIP")        
        self.in_sip_msg = 0
        return
    
    def parse_line(self, line, claimed=False):

        #if(claimed):
        #    if(self.in_sip_msg):
        #        self.submit_sip_message()
        #    return False
        # print line
        # are we in the part of the SIPS log that is a SIP Message?
        if(self.in_sip_msg):
            self.in_sip_msg += 1
            if(self.in_sip_msg == 2): # first line
                if(line[:7] == 'SIP/2.0'):
                    self.d_sip_msg['method'] = line[8:].rstrip()
                #else:
                #    self.d_sip_msg['method'] = (line.split())[0]    
            else:    
                # call id?
                if not 'call_id' in self.d_sip_msg.keys():
                    _re_call_id = self.pattern_sip_call_id.match(line)
                    if(_re_call_id):
                        self.d_sip_msg['call_id'] = _re_call_id.group(1).rstrip()
                # checking for the end, and sending
                if(self.match_time_stamp(line)):
                    self.submit_sip_message()
                    return self.parse_line(line)
                #else:

            self.sip_msg = self.sip_msg + line
            return True
        
        # we are not, looking for the beggining of the SIP Message  
        else:
            # scout for time stamps
            if(self.match_time_stamp(line)):
            #print "-- match?"
                self.re_line = self.pattern_sip_msg_received.match(line)
                if(self.re_line):
                    self.init_sip_message(self.re_line.group(2))
                    #self.sip_msg = self.sip_msg + self.re_line.group(2)
                    self.d_sip_msg['from'] = self.re_line.group(1)  
                    self.d_sip_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                    return True
                else:
                    self.re_line = self.pattern_sip_msg_sent.match(line)
                    if(self.re_line):
                        self.init_sip_message(self.re_line.group(2))
                        #self.match_time_stamp(self.re_line.group(1))
                        #self.d_sip_msg['@datetimestr'] = self.re_line.group(1) 
                        #self.sip_msg = self.sip_msg + self.re_line.group(2)                   
                        self.d_sip_msg['to'] = self.re_line.group(1)
                        self.d_sip_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                        return True

#            if(self.pattern_std_msg.match(line)): 
#                self.submitter.submit(line)
                    
        return False

    def __del__(self):
        logging.debug("SIPGVPMsgParser __del__")
        if(self.in_sip_msg):
            self.submit_sip_message()
        LogParser.__del__(self)
        return