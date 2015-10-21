from LogParser import LogParser
import re
#from logger import submitter
from datetime import date, datetime, timedelta


class StdLibParser(LogParser):

    """ date and time pattern """
    pattern_std_msg = re.compile(r'(Std|Trc|Int|Alr) (.+)$')
    
    def __init__(self,submitter,tags={}):
        LogParser.__init__(self, submitter,tags)
        # dictionary for SIP msg
        self.d_std_msg = {}
        
    def parse_line(self, line, claimed=False):
        if(claimed):
            return False
        if(self.match_time_stamp(line)):
            self.re_line = self.pattern_std_msg.search(line)
            if(self.re_line): 
                #self.submitter.submit(line)
                self.d_std_msg = self.d_common_tags.copy()
                self.d_std_msg['message'] = self.re_line.group(0)
                self.d_std_msg['log_level'] = self.re_line.group(1)                
                self.d_std_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                self.submitter.d_submit_f(self.d_std_msg,"StdLib")
                return True
        else:
            return False
    
    
