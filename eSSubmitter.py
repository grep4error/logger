#import sys
#import json
from Submitter import Submitter
from elasticsearch import Elasticsearch,helpers
from datetime import datetime
import logging
from sys import exc_info


class eSSubmitter(Submitter):

             
    def __init__(self, fields = '', formats = {}, eSurl = 'http://localhost:9200', chunk_size = 900):
        Submitter.__init__(self, fields, formats)
        #logging.info("eSSubmitter init: "+fields+" : "+str(formats))
        self.eS = Elasticsearch(eSurl)       
        self.actions = []
        self.chunk_size = chunk_size
        return

    def json_serial(self,obj):
        # JSON serializer for objects not serializable by default json code
        if isinstance(obj, datetime):
            serial = obj.isoformat()
            return serial
        raise TypeError ("Type not serializable")
            
    def d_submit(self,d_msg,msg_type='log'):
        #print "------------------------------------------"
        self.es_index = 'logstash-' + d_msg['@timestamp'].strftime('%Y%m%d')
        #print self.es_index
        # add _index (and _type?)
        
        self.op_data = {
            "_index":self.es_index,
            "_type":msg_type,
            "_source":d_msg.copy()}
        logging.debug('message: '+str(self.op_data))
        #self.json_msg_body = json.dumps(d_msg,default=self.json_serial)
        #print self.json_msg_body
        if (len(self.actions) < self.chunk_size):
            self.actions.append(self.op_data)
        else:    
            try:
                self.bulk_result = helpers.bulk(self.eS, self.actions, stats_only = False)
            except:
                logging.error("RETRYING eS bulk...")
                self.bulk_result = helpers.bulk(self.eS, self.actions, stats_only = False)

                
            self.actions = []
            logging.info("result of elasticsearch bulk: "+ str(self.bulk_result))
        #for key in d_msg:
        #    print key + " : " + str(d_msg[key])
        # self.eS.index(index=self.es_index, doc_type='log', id=uuid.uuid1(), body=self.json_msg_body)

        return

    def __del__(self):
        try:
            self.bulk_result = helpers.bulk(self.eS, self.actions, stats_only = False)
        except:
            logging.error("RETRYING final eS bulk...")
            self.bulk_result = helpers.bulk(self.eS, self.actions, stats_only = False)
            
        logging.info("result of final elasticsearch bulk: "+str(self.bulk_result))
        
        return