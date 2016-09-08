import Submitter
import re
from datetime import date, datetime, timedelta
import sys
import logging


class LogParser:
    # static vars
    # date and time patterns
    pattern_time_only = re.compile(r'^(@)?(\d{2}):(\d{2}):(\d{2}).(\d{3,4})')
    pattern_time_date = re.compile(r'(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2}).(\d{3,4})')

    # let's see if combining two will speed up matching
    pattern_timestamp = re.compile(r'^(?:@)?(\d{2}):(\d{2}):(\d{2}).(\d{3,4})|^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2}).(\d{3,4})')

    # the file may have time and date in it's name that can be used for setting the initial time reference
    # it looks like this 20150619_111018
    pattern_file_time_date = re.compile(r'(\d{4})(\d{2})(\d{2})_(\d{2})(\d{2})(\d{2})')
 
    timestamp_begin = set(['0','1','2','3','4','5','6','7','8','9','@'])
 
    # date and time are class variables
    # current date, today by default
    cur_date = {"y":0, "m":0, "d":0}
    # time
    cur_time = {"h":0, "m":0, "s":0, "ms":0}
    
    # Application name: SIPS_B
    pattern_app_name = re.compile(r'Application name:\t(.+)$')
    
    # Host name:        USW1VMB-060-001.USW1.GENPRIM.COM
    pattern_host_name = re.compile(r'Host name:\t(.+)$')

    
    def __init__(self,submitter,tags={}):
        logging.debug("LogParser __init__")

        # current date, today by default
        # self.cur_date = {"y":0, "m":0, "d":0}
        # time
        # self.cur_time = {"h":0, "m":0, "s":0, "ms":0}
        
        # datetime var
        # self.cur_datetime = datetime.now()
        self.d_common_tags = tags
        logging.debug('LogParser __init__ setting tags to :'+ str(self.d_common_tags))

        self.submitter = submitter
        return
    
    def get_type(self):
        return 'log'
    
    def parse_line(self, line, claimed=False, line_num=0):
        # claimed indicates that a parser called before alse recognised this line as a match
        self.submitter.submit(line)
        return True

    def increment_date(self):
        date_now = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
        date_new = date_now + timedelta(days=1)
        self.cur_date['y'] = date_new.year
        self.cur_date['m'] = date_new.month
        self.cur_date['d'] = date_new.day
        # 
        return

    def detect_common_headers(self,line):
        if(not self.d_common_tags['host_name']):
            self.host_name_match = self.pattern_host_name(line)
            if(self.host_name_match):
                self.d_common_tags['host_name'] = self.host_name_match.group(1)
                
        if(not self.d_common_tags['app_name']):            
            self.app_name_match = self.pattern_app_name(line)
            if(self.app_name_match):
                self.d_common_tags['app_name'] = self.app_name_match.group(1)
        return

    def set_file(self, file_name):
        logging.info("setting file: "+file_name)
        self.d_common_tags['file'] = file_name
        self.check_time_date = self.pattern_file_time_date.search(file_name) 

        #print "-- re: " + self.check_time_date
        if(self.check_time_date):
            # set date
            self.cur_date['y'] = int(self.check_time_date.group(1))
            self.cur_date['m'] = int(self.check_time_date.group(2))
            self.cur_date['d'] = int(self.check_time_date.group(3))
            # and time
            self.cur_time['h'] = int(self.check_time_date.group(4))
            self.cur_time['m'] = int(self.check_time_date.group(5))
            self.cur_time['s'] = int(self.check_time_date.group(6))
            
            logging.info("setting date from file: "+str(self.cur_date['y'])+'/'+str(self.cur_date['m'])+'/'+str(self.cur_date['d']))
        return
    
    def match_time_stamp(self,str_to_match):
        # logging.debug("matching time stamp")
        self.match_result = self.pattern_timestamp.match(str_to_match)
        if(self.match_result):
            # print(str(self.match_result.lastindex)+" - "+str_to_match)
            if(self.match_result.lastindex == 11): # date and time
                # set date
                self.cur_date['y'] = int(self.match_result.group(5))
                self.cur_date['m'] = int(self.match_result.group(6))
                self.cur_date['d'] = int(self.match_result.group(7))
                # and time
                self.cur_time['h'] = int(self.match_result.group(8))
                self.cur_time['m'] = int(self.match_result.group(9))
                self.cur_time['s'] = int(self.match_result.group(10))  
                __str_msec = self.match_result.group(11) + '00'

                if(len(__str_msec) == 5):
                    __str_msec = __str_msec + '0'
                    
                self.cur_time['ms'] = int(__str_msec)  
                return True
            else:  # date only
                # and time
                __str_msec = self.match_result.group(4) + '00'
                if(len(__str_msec) == 5):
                    __str_msec = __str_msec + '0'
                __int_hour   = int(self.match_result.group(1))
                __int_minute = int(self.match_result.group(2))
                __int_second = int(self.match_result.group(3))
                __int_msec   = int(__str_msec)
                # lazy cheking for midnight rollover
            
                if(__int_hour < self.cur_time['h']):
                    self.increment_date()
            
                self.cur_time['h']  = __int_hour
                self.cur_time['m']  = __int_minute
                self.cur_time['s']  = __int_second
                self.cur_time['ms'] = __int_msec
                return True
                            
        return False

    def match_time_stamp_old(self,str_to_match):
        self.match_result = self.pattern_time_date.match(str_to_match)
        if(self.match_result):
            # set date
            self.cur_date['y'] = int(self.match_result.group(1))
            self.cur_date['m'] = int(self.match_result.group(2))
            self.cur_date['d'] = int(self.match_result.group(3))
            # and time
            self.cur_time['h'] = int(self.match_result.group(4))
            self.cur_time['m'] = int(self.match_result.group(5))
            self.cur_time['s'] = int(self.match_result.group(6))  
            __str_msec = self.match_result.group(7) + '00'

            if(len(__str_msec) == 5):
                __str_msec = __str_msec + '0'
                    
            self.cur_time['ms'] = int(__str_msec)  
            return True
        self.match_result = self.pattern_time_only.match(str_to_match)
        if(self.match_result):
            # and time
            __str_msec = self.match_result.group(5) + '00'
            if(len(__str_msec) == 5):
                __str_msec = __str_msec + '0'
            __int_hour   = int(self.match_result.group(2))
            __int_minute = int(self.match_result.group(3))
            __int_second = int(self.match_result.group(4))
            __int_msec   = int(__str_msec)
            # lazy cheking for midnight rollover
            
            if(__int_hour < self.cur_time['h']):
                self.increment_date()
            
            self.cur_time['h']  = __int_hour
            self.cur_time['m']  = __int_minute
            self.cur_time['s']  = __int_second
            self.cur_time['ms'] = __int_msec
            return True
                            
        return False
    
    def __del__(self):
        logging.debug("LogParser __del__")
        return