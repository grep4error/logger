import sys
import logging
from __builtin__ import next

class Submitter:
    def __init__(self,fields = '',formats = {}):
        logging.debug( "Submitter __init__" )
        self.fields = fields.split(',')
        self.formats = formats;
        self.formats_set = set(self.formats); # use set and intersection method, quicker than going through dicts
        self.use_formats = len(self.formats)
        
        logging.info("submitter fields set to:  " + str(self.fields))
        if(self.use_formats):
            logging.info("submitter formats set to: " + str(self.formats))
        return
        
    def submit(self,msg):
        print msg
        return
    
    def d_submit(self, d_msg, msg_type='log'):
        logging.debug("-------------------- default submitter ----------------------")
        if(self.fields == ''):
            for key in d_msg:
                sys.stdout.write( key + " : " + str(d_msg[key]) + "\n")
        else:
            for key in self.fields:
                if key in d_msg.keys():
                    sys.stdout.write(key + " : " + str(d_msg[key]) + "\n")        
        return

# formatted submit
# on a second thought, Kibana can format fields for you, 
# and that is the right approach... so I am taking this OUT...

    def d_submit_f(self, d_msg, msg_type='log' ):
# format fields
        logging.debug("formatted submit")
        if(self.use_formats):
            self.d_msg_set = set(d_msg)
        
            for field_name in self.formats_set.intersection(self.d_msg_set):
                d_msg[field_name] = self.formats[field_name].format(d_msg[field_name])
        
        self.d_submit(d_msg, msg_type)            
        return
    
class SubmitterError(Exception):
    pass
