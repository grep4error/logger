from LogParser import LogParser
import re, sys
from datetime import datetime
#from logger import submitter
import logging

class SIPSMsgParser(LogParser):
    # static vars

    # beginning of SIP message received by SIP Server
    # 16:45:03.031: SIPTR: Received [0,UDP] 467 bytes from 10.51.34.110:5060 <<<<<
    # pattern_sip_msg_received = re.compile('^(\S+)(?::|) SIPTR: Received \[\S+\] \d+ bytes from (\S+) <<<<<$')
    pattern_sip_msg_received = re.compile('^([0-9.:]+)(?::|) SIPTR: Received \[\S+\] \d+ bytes from ([0-9.:]+) <<<<<$')

    # beggining of a SIP message sent by SIP Server
    # 16:45:04.720: Sending  [0,UDP] 406 bytes to 10.51.34.110:5060 >>>>>
    pattern_sip_msg_sent = re.compile('^([0-9.:]+)(?::|) Sending  \[\S+\] \d+ bytes to ([0-9.:]+) >>>>>$')
    # Call-ID: ...
    pattern_sip_call_id = re.compile('Call-ID: (.+)$', re.IGNORECASE)    
 
     
    def __init__(self,submitter,tags={}):
        logging.debug("SIPSMsgParser __init__")
        LogParser.__init__(self, submitter,tags)
        # buffer
        self.sip_msg = ''
        # dictionary for SIP msg
        self.d_sip_msg = {}
        # bool we are in sip msg
        self.in_sip_msg = 0

        
    def init_sip_message(self):
        self.in_sip_msg = 1
        self.sip_msg = ''
        #self.d_sip_msg.clear()
        self.d_sip_msg = self.d_common_tags.copy()
        return
    
    def submit_sip_message(self):
        #print "-- end of SIP msg"
        self.d_sip_msg['message'] = self.sip_msg
        self.submitter.d_submit(self.d_sip_msg,"SIP")        
        self.in_sip_msg = 0
        return
    
    def parse_line(self, line, claimed=False):
        if(claimed):
            if(self.in_sip_msg):
                self.submit_sip_message()
            return False
        # print line
        # are we in the part of the SIPS log that is a SIP Message?
        if(self.in_sip_msg):
            self.in_sip_msg += 1
            if(self.in_sip_msg == 2): # first line
                if(line[:7] == 'SIP/2.0'):
                    self.d_sip_msg['method'] = (line[8:].rstrip())[:4096]
                else:
                    self.d_sip_msg['method'] = ((line.split())[0])[:4096]    
            else:    
                # call id?
                if not 'call_id' in self.d_sip_msg.keys():
                    _re_call_id = self.pattern_sip_call_id.match(line)
                    if(_re_call_id):
                        self.d_sip_msg['call_id'] = (_re_call_id.group(1).rstrip())[:4096]
                # checking for the end, and sending

                if(line[0] in self.timestamp_begin):
                    if(self.match_time_stamp(line)):
                        self.submit_sip_message()
                        return self.parse_line(line)
                #else:

            self.sip_msg = self.sip_msg + line
            return True
        
        # we are not, looking for the beggining of the SIP Message  
        else:
            # scout for time stamps
            if(line[0] not in self.timestamp_begin):
                return False
            if(self.match_time_stamp(line)):
            #print "-- match?"
                self.re_line = self.pattern_sip_msg_received.match(line)
                if(self.re_line):
                    self.init_sip_message()
                    self.match_time_stamp(self.re_line.group(1))
                    #self.d_sip_msg['@datetimestr'] = self.re_line.group(1)
                    self.d_sip_msg['from'] = (self.re_line.group(2))[:4096]  
                    self.d_sip_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                else:
                    self.re_line = self.pattern_sip_msg_sent.match(line)
                    if(self.re_line):
                        self.init_sip_message()
                        self.match_time_stamp(self.re_line.group(1))
                        #self.d_sip_msg['@datetimestr'] = self.re_line.group(1)                    
                        self.d_sip_msg['to'] = (self.re_line.group(2))[:4096]
                        self.d_sip_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])

#            if(self.pattern_std_msg.match(line)): 
#                self.submitter.submit(line)
                    
        return False

    def __del__(self):
        logging.debug("SIPSMsgParser __del__")
        if(self.in_sip_msg):
            self.submit_sip_message()
        LogParser.__del__(self)
        return