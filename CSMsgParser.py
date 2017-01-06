from LogParser import LogParser
import re, sys
from datetime import datetime
#from logger import submitter
import logging


class CSLogMessageType:
        Unknown,ClientRequest, ServerResponce, ServerResponceDetail = range(4)

class CSMsgParser(LogParser):
    # static vars

    # 2016-11-25T12:25:19.644 Trc 04541 Message MSGCFG_GETOBJECTINFO received from 16 (SCE 'default')
    #
    #  MSGCFG_GETOBJECTINFO
    #  attr: IATRCFG_REQUESTID           value:   90
    #  attr: IATRCFG_OBJECTTYPE          value:   9 [CfgApplication]
    #  attr: BATRCFG_FILTER              value:
    #
    #  Filter :
    #   key: name                        type:    [String], value : default
    #   key: object_path                 type:    [Integer], value : 0
    #   key: read_folder_dbid            type:    [Integer], value : 0
    #  Query  : CfgApplication[ (@name = 'default')]
    # ..... also covers ....
    # Trc 04541 Message MSGCFG_GETOBJECTINFO received from 644 (InteractionWorkspace  'Workspace')
    # Trc 04541 Message MSGCFG_GETOBJPERMISSIONS received from 18 (SCE 'default')
    # Trc 04541 Message MSGCFG_GETBRIEF...
    # Trc 04541 Message MSGCFG_GETOBJECTINFOEX
    # Trc 04541 Message MSGCFG_GETSERVERPROTOCOL
    # [optional, if sync] Trc 04541 Message MSGCFG_CLIENTREGISTER
    # [optional, if sync] Trc 04541 Message MSGCFG_AUTHENTICATE
    # 2016-11-25T11:25:20.336 Trc 04541 Message MSGCFG_AUTHENTICATE received from 55 (GenericClient 'Cloud')
    # 2016-11-25T11:25:20.339 Trc 04542 Message MSGCFG_AUTHENTICATED sent to 55 (GenericClient 'Cloud')
    pattern_cs_msg_received = re.compile('^(\S+) Trc 04541 Message (\S+)\s+(.+)') #(\S+) received .+\((\.+)\)$')

    # 2016-11-25T12:25:19.645 Trc 04542 Message MSGCFG_ENDOBJECTSLIST sent to 16 (SCE 'default')
    #
    #  MSGCFG_ENDOBJECTSLIST
    #  attr: IATRCFG_OBJECTTYPE          value:   9 [CfgApplication]
    #  attr: IATRCFG_REQUESTID           value:   90
    #
    # ..... also covers ......
    # Trc 04542 Message MSGCFG_ENDOBJECTSLIST sent to 326 (InteractionWorkspace  'Workspace')
    # Trc 04542 Message MSGCFG_OBJPERMISSIONS sent to 18 (SCE 'default')
    # Trc 04542 Message MSGCFG_SERVERPROTOCOL
    # [optional, --isregsync] Trc 04541 Message MSGCFG_CLIENTREGISTER
    # [optional, --isregsync] Trc 04541 Message MSGCFG_AUTHENTICATE
    # 2016-11-25T11:25:20.339 Trc 04542 Message MSGCFG_AUTHENTICATED sent to 55 (GenericClient 'Cloud')
    pattern_cs_msg_responce = re.compile('^(\S+) Trc 04542 Message (\S+)\s+(.+)') #(\S+) sent .+\((\.+)\)$')

    # 2016-11-25T12:25:19.645 Trc 24215 There are [1] objects of type [CfgApplication] sent to the client [16] (application [default], type [SCE])
    pattern_cs_results_sent = re.compile('^(\S+) Trc 24215 There are (\S+)\s+(.+)')



     
    def __init__(self,submitter,tags={}):
        logging.debug("CSMsgParser __init__")
        LogParser.__init__(self, submitter,tags)
        # buffer
        self.cs_msg = ''
        # dictionary for current CS msg
        self.d_cs_msg = {}
        # bool we are in CS msg
        self.in_cs_msg = 0
        # dictionary for messages per clients that are currently pending future processing
        self.d_cs_clients_msgs = {}

        
    def init_cs_message(self):
        self.in_cs_msg = 1
        self.cs_msg = ''
        #self.d_cs_msg.clear()
        self.d_cs_msg = self.d_common_tags.copy()
        self.d_cs_msg['csmsgclass']= CSLogMessageType.Unknown
        return
    
    def submit_cs_message(self):
        self.d_cs_msg['message'] = self.cs_msg
        # TODO: only submit messages into submiter when processing has been completed (we have matching responce. maybe check for timeout, client disconnect, etc?)
        is_ready_for_push = False
        if (self.d_cs_msg['csmsgclass']==CSLogMessageType.ClientRequest):
            is_ready_for_push = self.process_cs_request_message()
        elif (self.d_cs_msg['csmsgclass']==CSLogMessageType.ServerResponce):
            is_ready_for_push = self.process_cs_responce_message()
        elif (self.d_cs_msg['csmsgclass']==CSLogMessageType.ServerResponceDetail):
            is_ready_for_push = self.process_cs_results_message()

        if is_ready_for_push:
            self.submitter.d_submit(self.d_cs_msg,"CS")
        self.in_cs_msg = 0
        return
    
    def parse_line(self, line, claimed=False):
        if(claimed):
            if(self.in_cs_msg):
                self.submit_sip_message()
            return False
        # print line
        # are we in the part of the CS log that is CS Message?
        if(self.in_cs_msg):

           if(line[0] in self.timestamp_begin):
                if(self.match_time_stamp(line)):
                    self.submit_cs_message()
                    return self.parse_line(line)

           self.cs_msg = self.cs_msg + line
           return True
        # we are not, looking for the beggining of the CS Message
        else:
            # scout for time stamps
            if(line[0] not in self.timestamp_begin):
                return False
            if(self.match_time_stamp(line)):
                self.re_line = self.pattern_cs_msg_responce.match(line)
                if(self.re_line):
                    self.init_cs_message()
                    self.match_time_stamp(self.re_line.group(1))
                    self.cs_msg =  line[len(self.re_line.group(1)):]
                    self.d_cs_msg['csmsgclass'] = CSLogMessageType.ServerResponce
                    self.d_cs_msg['request'] = (self.re_line.group(2))[:4096]
                    # self.d_cs_msg['details'] = (self.re_line.group(3))[:4096]
                    self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                    return True
                else:
                    self.re_line = self.pattern_cs_msg_received.match(line)
                    if(self.re_line):
                        self.init_cs_message()
                        self.match_time_stamp(self.re_line.group(1))
                        self.cs_msg = line[len(self.re_line.group(1)):]
                        self.d_cs_msg['csmsgclass'] = CSLogMessageType.ClientRequest
                        self.d_cs_msg['request'] = (self.re_line.group(2))[:4096]
                        # self.d_cs_msg['details'] = (self.re_line.group(3))[:4096]
                        self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'],self.cur_date['m'],self.cur_date['d'],self.cur_time['h'],self.cur_time['m'],self.cur_time['s'],self.cur_time['ms'])
                        return True
                    else:
                        self.re_line = self.pattern_cs_results_sent.match(line)
                        if (self.re_line):
                            self.init_cs_message()
                            self.match_time_stamp(self.re_line.group(1))
                            self.cs_msg = line[len(self.re_line.group(1)):]
                            # self.d_cs_msg['@datetimestr'] = self.re_line.group(1)
                            self.d_cs_msg['csmsgclass'] = CSLogMessageType.ServerResponceDetail
                            # self.d_cs_msg['details'] = (self.re_line.group(2))[:4096]
                            self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'], self.cur_date['m'],
                                                                   self.cur_date['d'], self.cur_time['h'],
                                                                   self.cur_time['m'], self.cur_time['s'],
                                                                   self.cur_time['ms'])
                            return True
        return False


    def process_cs_request_message(self):
        lines = self.cs_msg.splitlines(1);
        if len(lines) >0  and lines[0]:
            tokens = lines[0].split();
            if len(tokens) >= 7:
                reqid = tokens[3]
                clientid = tokens[6]
                pc = self.cs_msg.find("IATRCFG_REQUESTID")
                if pc != -1:
                    pce = self.cs_msg.find('\n', pc + 37)
                    refid = self.cs_msg[pc + 37:pce]
                    ''' Get Query '''
                    reqquery = ''
                    qp = self.cs_msg.find("Query  :")
                    if qp != -1:
                        qe = self.cs_msg.find('\n', qp + 9)
                        reqquery = self.cs_msg[qp + 9:qe]
                    ''' Add to pool '''
                    if not clientid in self.d_cs_clients_msgs:
                        self.d_cs_clients_msgs[clientid] = {}
                    if not refid in self.d_cs_clients_msgs[clientid]:
                        self.d_cs_clients_msgs[clientid][refid] = {}
                    self.d_cs_clients_msgs[clientid][refid] = self.d_cs_msg
                    self.d_cs_msg['reqid'] = refid
                    self.d_cs_msg['clientid'] = clientid
                    self.d_cs_msg['query'] = reqquery
                    return False # we will push request after we update it with details from server's responce: TBD what to do if no responce/timeout/disconnect
            logging.info("Ignored request (wrong format): " + str(self.d_cs_msg))

        else:
            logging.info("Ignored request (wrong format): "+ str(self.d_cs_msg) )

        return True # this is unknown request/client , push it as is

    def process_cs_responce_message(self):
        lines = self.cs_msg.splitlines(1);
        if len(lines) > 0 and lines[0]:
            tokens = lines[0].split();
            if len(tokens) >= 7:
                clientid = tokens[6]
                pc = self.cs_msg.find("IATRCFG_REQUESTID")
                if pc != -1:
                    pce = self.cs_msg.find('\n', pc + 37)
                    refid = self.cs_msg[pc + 37:pce]
                    ''' Check if request exists in pool '''
                    reqfound = False
                    if clientid in self.d_cs_clients_msgs:
                        if refid in self.d_cs_clients_msgs[clientid]:
                            reqfound = True
                            reqdt = self.d_cs_clients_msgs[clientid][refid]['@timestamp']
                            resdt = self.d_cs_msg['@timestamp']
                            dtdiff = resdt - reqdt
                            msdelta = int(dtdiff.total_seconds() * 1000)
                            #if self.requestsPool[clientid][refid]['reqid'] == "MSGCFG_GETOBJECTINFO" or \
                            #                self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_GETBRIEFINFO' or \
                            #                self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_GETOBJPERMISSIONS' or \
                            #                self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_GETOBJECTINFOEX' or \
                            #                self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_GETSERVERPROTOCOL' or \
                            #                (self.isregistersync and self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_CLIENTREGISTER') or \
                            #                (self.isregistersync and self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_AUTHENTICATE'):
                            #    """ Time,ClientID,RefId,Request,Duration,Query,ObjectType,ObjectNum,Start,End,StartFile,StartLine,EndFile,EndLine """
                            #    self.outfile.write(resdt.strftime('%m-%dT%H:%M:%S') + ',' + clientid + ',' + refid + ',')
                            #    self.outfile.write(self.requestsPool[clientid][refid]['reqid'] + ',')
                            #    self.outfile.write(str(msdelta) + ',')
                            #    self.outfile.write('"' + self.requestsPool[clientid][refid]['query'] + '",')
                            #    if self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_GETOBJPERMISSIONS':
                            #        self.outfile.write('CfgACE,1,')
                            #    elif (self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_CLIENTREGISTER' or  self.requestsPool[clientid][refid]['reqid'] == 'MSGCFG_AUTHENTICATE'):
                            #        self.outfile.write('RegisterEventSync,1,')
                            #    else:
                            #        self.outfile.write(self.lastObjectSent + ',' + str(self.lastObjectSentNum) + ',')
                            #    self.outfile.write(sreqdt + ',')
                            #    self.outfile.write(sresdt + ',')
                            #    self.outfile.write(self.requestsPool[clientid][refid]['file'] + ',')
                            #    self.outfile.write(str(self.requestsPool[clientid][refid]['line']) + ',')
                            #    self.outfile.write(self.filename + ',')
                            #    self.outfile.write(str(self.lineCntr - 1))
                            #    self.outfile.write('\n')
                            #    self.msgcntr=self.msgcntr+1
                            self.d_cs_msg = self.d_cs_clients_msgs[clientid][refid].copy()
                            self.d_cs_msg['duration'] = msdelta
                            del self.d_cs_clients_msgs[clientid][refid]
                            return True # responce has been updated, push self.d_cs_msg to submiter

                    logging.info("Ignored responce (no match): " + str(self.d_cs_msg))
        else:
            logging.info ("Ignored responce (wrong format): " +str(self.d_cs_msg))
        return False # this is unknown responce, do not push to storage


    def process_cs_results_message(self):
        lines = self.cs_msg.splitlines(1);
        if len(lines) > 0 and lines[0]:
            tokens = lines[0].split();
            if len(tokens) >= 14:
                tnum = tokens[4]
                snum = tnum[1:-1]
                num = int(snum)
                tobj = tokens[8]
                sobj = tobj[1:-1]
                tclientid = tokens[13]
                clientid = tclientid [1:-1]
                is_request_found = False
                if clientid in self.d_cs_clients_msgs:
                    for refid in self.d_cs_clients_msgs[clientid]:
                        if self.d_cs_clients_msgs[clientid][refid]['request']:
                            if (self.d_cs_clients_msgs[clientid][refid]['request'].startswith("MSGCFG_GETOBJECT") or
                                self.d_cs_clients_msgs[clientid][refid]['request'].startswith("MSGCFG_GETBRIEF")):
                                    is_request_found = True
                                    self.d_cs_clients_msgs[clientid][refid]['objcntr'] = num
                                    self.d_cs_clients_msgs[clientid][refid]['objtype'] = sobj

                if (not is_request_found):
                    logging.info("Ingnored detail message (no match): " +str(self.d_cs_msg) )

        return False # result message shoudl be discarded (will push updated entry when we process final responce msg)



    def __del__(self):
        logging.debug("SIPSMsgParser __del__")
        if(self.in_cs_msg):
            self.submit_cs_message()
        LogParser.__del__(self)
        return