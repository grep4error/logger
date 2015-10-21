from Submitter import Submitter

# THIS SUBMITTER IS NO LONGER USED, IMPLEMENTED IN CSVPrintSubmitter.py 
#
# This output can be fed into postgres
# CREATE TABLE sip_msgs (id serial,sip_datetime timestamp,sip_to varchar(40),sip_from varchar(40),sip_method varchar(40),sip_call_id varchar(120));
# 
# output to a file, then import csv to sip_msgs
# \copy sip_msgs(sip_datetime,sip_to,sip_from,sip_method,sip_call_id) FROM '/path/to/csv/sip_msgs.csv' DELIMITER ',' CSV 
#
# sample select (find cancelled dialogs longer than 10 sec.)
# select a.sip_datetime,a.sip_call_id,a.sip_datetime - b.sip_datetime from sip_msgs a, sip_msgs b 
# where a.sip_call_id = b.sip_call_id and a.sip_from = '10.51.34.60:5060' and a.sip_method = 'CANCEL' 
# and b.sip_method = 'INVITE' and date_part('epoch',a.sip_datetime - b.sip_datetime)>10 \g 'D:\saas\logger\gec-2623-1.out'


class SIPPrintSubmitter(Submitter):

    def d_submit(self,d_msg,msg_type='log'):
        self.out = ''
        
        if '@timestamp' in d_msg.keys():
            self.out += str(d_msg['@timestamp'])
        self.out += ','

        if 'to' in d_msg.keys():
            self.out += d_msg['to']
        self.out += ','
            
        if 'from' in d_msg.keys():
            self.out += d_msg['from']
        self.out += ","
                            

        if 'method' in d_msg.keys():
            self.out += d_msg['method']
        self.out += ","

        if 'call_id' in d_msg.keys():
            self.out += d_msg['call_id']
        
        print self.out

    
        #for key in d_msg:
        #    print key + " : " + str(d_msg[key])
        return