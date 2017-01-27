from LogParser import LogParser
import re, sys
from datetime import datetime
#from logger import submitter
import logging


class CSLogMessageType:
        Unknown, \
        ClientRequest, ServerResponce, ServerResponceDetail, \
        ExtAuthRequest,ExtAuthRequestAccepted, \
        ExtAuthInitConnection, ExtAuthInitConnectionAccepted, ExtAuthBIND, ExtAuthClosed = range(10)

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
    # [optional] Trc 04542 Message MSGCFG_CLIENTREGISTERED
    # 2016-11-25T11:25:20.339 Trc 04542 Message MSGCFG_AUTHENTICATED sent to 55 (GenericClient 'Cloud')
    pattern_cs_msg_responce = re.compile('^(\S+) Trc 04542 Message (\S+)\s+(.+)') #(\S+) sent .+\((\.+)\)$')

    # 2016-11-25T12:25:19.645 Trc 24215 There are [1] objects of type [CfgApplication] sent to the client [16] (application [default], type [SCE])
    pattern_cs_results_sent = re.compile('^(\S+) Trc 24215 There are (\S+)\s+(.+)')

    # AUT_MAIN: 20:33:12.879 AUT_MAIN: Put request to queue. Request ID = 2
    pattern_cs_extauth_put = re.compile('^(\S+) AUT_MAIN: Put request to queue. Request ID = (\S+)') # to match main thread submit request

    # 20:33:12.910 AUT_DBG: Authentication request received. Request ID = 2
    pattern_cs_extauth_put_accept = re.compile('^(\S+) AUT_DBG: Authentication request received. Request ID = (\S+)') # to match ext auth thread pull request

    # 20:33:12.740 AUTH_DBG: Initialized data for connection to LDAP server: localhost:389...
    pattern_cs_extauth_conn_init = re.compile('^(\S+) AUTH_DBG: Initialized data for connection to LDAP server: (\S+)')

    # 20:33:12.741 AUTH_DBG: BIND sent for request ID: -1, LDAP message ID: 1 Connection: ldap://localhost:389 (0xd50:1:0)
    pattern_cs_extauth_conn_bind = re.compile('^(\S+) AUTH_DBG: BIND sent for request ID: (-?[0-9]+), LDAP message ID: (-?[0-9]+) Connection: ldap\w?://(\S+)') # search == -1, bind == actual request

    # 20:33:12.741 AUTH_DBG: Connection type 1 is initialized.
    pattern_cs_extauth_conn_inited = re.compile('^(\S+) AUTH_DBG: Connection type (\d+) is initialized') # type==1 - search, 2-bind

    # 20:04:11.054 AUTH_DBG: Connection ldaps://WIN-9MQ5RBO1DVT.gentn.com:636 (0xec024130:1:6) was closed.
    # 20:04:11.055 AUTH_DBG: Connection ldaps://WIN-9MQ5RBO1DVT.gentn.com:636 (0xec08ad90:2:6) was closed.
    pattern_cs_extauth_conn_close = re.compile('^(\S+) AUTH_DBG: Connection ldap\w?://(\S+) \(\w+:(\d):(\d)\) was closed')  # second group denote conenction type: 1- search, 2-bind





     
    def __init__(self,submitter,tags={}):
        logging.debug("CSMsgParser __init__")
        LogParser.__init__(self, submitter,tags)
        # buffer
        self.cs_msg = ''
        # dictionary for current CS msg
        self.d_cs_msg = {}
        # dictonary for previous CS message TODO: do we need a full stack ?
        self.d_cs_msg_stack =[]

        # bool we are in CS msg
        self.in_cs_msg = 0
        # we are handling termination (cleanup caches)
        self.in_shutdown = False
        # dictionary for messages per clients that are currently pending future processing
        self.d_cs_clients_msgs = {}
        # aux dictionary for ext auth module requests by internal reqid_exta (linked to d_cs_clients_msgs
        self.d_cs_exta_msgs= {}
        # dictonary for ext auth operations messages by ext auth endpoint
        self.d_cs_exta_intops={}


        
    def init_cs_message(self):
        self.in_cs_msg = 1
        self.cs_msg = ''
        #self.d_cs_msg.clear()
        if self.d_cs_msg_stack:
            self.d_cs_msg_stack.pop(0)
        self.d_cs_msg_stack.append(self.d_cs_msg) # last processed message into stack
        self.d_cs_msg = self.d_common_tags.copy()
        self.d_cs_msg['csmsgclass']= CSLogMessageType.Unknown
        self.d_cs_msg['vararg0'] =None
        self.d_cs_msg['vararg1'] = None
        self.d_cs_msg['vararg2'] = None
        return
    
    def submit_cs_message(self):
        if self.cs_msg:
            self.d_cs_msg['message'] = self.cs_msg
        # only submit messages into submiter when processing has been completed (we have matching responce. maybe check for timeout, client disconnect, etc?)
        # exception is if we are shutting down, then submit as is
        is_ready_for_push = False
        if self.in_shutdown:
            is_ready_for_push = True
        elif (self.d_cs_msg['csmsgclass']==CSLogMessageType.ClientRequest):
            is_ready_for_push = self.process_cs_request_message()
        elif (self.d_cs_msg['csmsgclass']==CSLogMessageType.ServerResponce):
            is_ready_for_push = self.process_cs_responce_message()
        elif (self.d_cs_msg['csmsgclass']==CSLogMessageType.ServerResponceDetail):
            is_ready_for_push = self.process_cs_results_message()
        elif (self.d_cs_msg['csmsgclass'])==CSLogMessageType.ExtAuthRequest:
            is_ready_for_push = self.process_exta_request_message()
        elif (self.d_cs_msg['csmsgclass'])==CSLogMessageType.ExtAuthRequestAccepted:
            is_ready_for_push = self.process_exta_accept_message()
        elif (self.d_cs_msg['csmsgclass'])==CSLogMessageType.ExtAuthInitConnection:
            is_ready_for_push = self.process_exta_initconn_message()
        elif (self.d_cs_msg['csmsgclass'])==CSLogMessageType.ExtAuthInitConnectionAccepted:
            is_ready_for_push = self.process_exta_acceptconn_message()
        elif (self.d_cs_msg['csmsgclass'])==CSLogMessageType.ExtAuthBIND:
            is_ready_for_push = self.process_exta_bind_message()
        elif (self.d_cs_msg['csmsgclass'])==CSLogMessageType.ExtAuthClosed:
            is_ready_for_push = self.process_exta_connclosed_message()

        if is_ready_for_push:
            if 'vararg0' in self.d_cs_msg:
                del self.d_cs_msg['vararg0'] # cleanup transient tags attached during parsing phase
            if 'vararg1' in self.d_cs_msg:
                del self.d_cs_msg['vararg1']
            if 'vararg2' in self.d_cs_msg:
                del self.d_cs_msg['vararg2']

            self.submitter.d_submit(self.d_cs_msg,"CS")
        self.in_cs_msg = 0
        return
    
    def parse_line(self, line, claimed=False):
        if(claimed):
            if(self.in_cs_msg):
                self.submit_cs_message()
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
                    self.d_cs_msg['method'] = (self.re_line.group(2))[:4096]
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
                        self.d_cs_msg['method'] = (self.re_line.group(2))[:4096]
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
                        else:
                            self.re_line = self.pattern_cs_extauth_put.match(line)
                            if (self.re_line):
                                self.init_cs_message()
                                self.match_time_stamp(self.re_line.group(1))
                                self.cs_msg = line[len(self.re_line.group(1)):]
                                self.d_cs_msg['csmsgclass'] = CSLogMessageType.ExtAuthRequest
                                self.d_cs_msg['vararg0'] = (self.re_line.group(2))[:4096] # extauth request id in debug message
                                self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'], self.cur_date['m'],
                                                                       self.cur_date['d'], self.cur_time['h'],
                                                                       self.cur_time['m'], self.cur_time['s'],
                                                                       self.cur_time['ms'])
                                return True
                            else:
                                self.re_line = self.pattern_cs_extauth_put_accept.match(line)
                                if (self.re_line):
                                    self.init_cs_message()
                                    self.match_time_stamp(self.re_line.group(1))
                                    self.cs_msg = line[len(self.re_line.group(1)):]
                                    self.d_cs_msg['csmsgclass'] = CSLogMessageType.ExtAuthRequestAccepted
                                    self.d_cs_msg['vararg0'] = (self.re_line.group(2))[
                                                               :4096]  # extauth request id in debug message
                                    self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'], self.cur_date['m'],
                                                                           self.cur_date['d'], self.cur_time['h'],
                                                                           self.cur_time['m'], self.cur_time['s'],
                                                                           self.cur_time['ms'])
                                else:
                                    self.re_line = self.pattern_cs_extauth_conn_init.match(line)
                                    if (self.re_line):
                                        self.init_cs_message()
                                        self.match_time_stamp(self.re_line.group(1))
                                        self.cs_msg = line[len(self.re_line.group(1)):]
                                        self.d_cs_msg['csmsgclass'] = CSLogMessageType.ExtAuthInitConnection
                                        self.d_cs_msg['vararg0'] = (self.re_line.group(2))[
                                                                   :4096]  # endpoint
                                        self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'], self.cur_date['m'],
                                                                               self.cur_date['d'], self.cur_time['h'],
                                                                               self.cur_time['m'], self.cur_time['s'],
                                                                               self.cur_time['ms'])
                                    else:
                                        self.re_line = self.pattern_cs_extauth_conn_inited.match(line)
                                        if (self.re_line):
                                            self.init_cs_message()
                                            self.match_time_stamp(self.re_line.group(1))
                                            self.cs_msg = line[len(self.re_line.group(1)):]
                                            self.d_cs_msg['csmsgclass'] = CSLogMessageType.ExtAuthInitConnectionAccepted
                                            self.d_cs_msg['vararg0'] = (self.re_line.group(2))[
                                                                       :4096]  # connection type
                                            self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'],
                                                                                   self.cur_date['m'],
                                                                                   self.cur_date['d'],
                                                                                   self.cur_time['h'],
                                                                                   self.cur_time['m'],
                                                                                   self.cur_time['s'],
                                                                                   self.cur_time['ms'])
                                        else:
                                            self.re_line = self.pattern_cs_extauth_conn_bind.match(line)
                                            if (self.re_line):
                                                self.init_cs_message()
                                                self.match_time_stamp(self.re_line.group(1))
                                                self.cs_msg = line[len(self.re_line.group(1)):]
                                                self.d_cs_msg['csmsgclass'] = CSLogMessageType.ExtAuthBIND
                                                self.d_cs_msg['vararg0'] = (self.re_line.group(2))[
                                                                           :4096]  # request id
                                                self.d_cs_msg['vararg1'] = (self.re_line.group(3))[
                                                                           :4096]  # ldap msg id
                                                self.d_cs_msg['vararg2'] = (self.re_line.group(4))[
                                                                           :4096]  # endpoint
                                                self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'],
                                                                                       self.cur_date['m'],
                                                                                       self.cur_date['d'],
                                                                                       self.cur_time['h'],
                                                                                       self.cur_time['m'],
                                                                                       self.cur_time['s'],
                                                                                       self.cur_time['ms'])
                                            else:
                                                self.re_line = self.pattern_cs_extauth_conn_close.match(line)
                                                if (self.re_line):
                                                    self.init_cs_message()
                                                    self.match_time_stamp(self.re_line.group(1))
                                                    self.cs_msg = line[len(self.re_line.group(1)):]
                                                    self.d_cs_msg['csmsgclass'] = CSLogMessageType.ExtAuthClosed
                                                    self.d_cs_msg['vararg0'] = (self.re_line.group(2))[
                                                                               :4096]  # endpoint
                                                    self.d_cs_msg['vararg1'] = (self.re_line.group(3))[
                                                                               :4096]  # type
                                                    self.d_cs_msg['vararg2'] = (self.re_line.group(4))[
                                                                               :4096]  # state
                                                    self.d_cs_msg['@timestamp'] = datetime(self.cur_date['y'],
                                                                                           self.cur_date['m'],
                                                                                           self.cur_date['d'],
                                                                                           self.cur_time['h'],
                                                                                           self.cur_time['m'],
                                                                                           self.cur_time['s'],
                                                                                           self.cur_time['ms'])



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
                    if not CSLogMessageType.ClientRequest in self.d_cs_clients_msgs[clientid][refid]:
                        self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest] = {}
                    self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest] = self.d_cs_msg
                    self.d_cs_msg['reqid'] = refid
                    self.d_cs_msg['clientid'] = clientid
                    self.d_cs_msg['query'] = reqquery
                    return False # we will push request after we update it with details from server's responce: TBD what to do if no responce/timeout/disconnect
            logging.info("Ignored request (wrong format): " + str(self.d_cs_msg))

        else:
            logging.info("Ignored request (wrong format): "+ str(self.d_cs_msg) )

        self.d_cs_msg['reqid'] = -1
        self.d_cs_msg['clientid'] = -1
        self.d_cs_msg['query'] = ''

        return True # this is unknown request/client , push it as is and create expected fields with empty values


    def process_exta_request_message(self):
        prev_msg = next(iter(self.d_cs_msg_stack or []), None)
        if prev_msg and prev_msg['csmsgclass']==CSLogMessageType.ClientRequest and (prev_msg['method']=='MSGCFG_CLIENTREGISTER' or prev_msg['method']=='MSGCFG_AUTHENTICATE'):
            reqid_exta = self.d_cs_msg['vararg0'] # store reference id  of mf_auth module request
            prev_msg['reqid_exta']=reqid_exta
            refid = prev_msg['reqid']
            self.d_cs_msg['reqid']= refid # and copy client ref id from cs request here
            self.d_cs_msg['reqid_exta']=reqid_exta
            clientid = prev_msg['clientid']
            self.d_cs_msg['clientid'] =clientid
            if not clientid in self.d_cs_clients_msgs:
                self.d_cs_clients_msgs[clientid] = {}
            if not refid in self.d_cs_clients_msgs[clientid]:
                self.d_cs_clients_msgs[clientid][refid] = {}
            if not CSLogMessageType.ExtAuthRequest in self.d_cs_clients_msgs[clientid][refid]:
                self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ExtAuthRequest] = {}
            self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ExtAuthRequest] = self.d_cs_msg
            if not reqid_exta in self.d_cs_exta_msgs:
                self.d_cs_exta_msgs[reqid_exta] = self.d_cs_msg
            else:
                logging.info("CS external auth request request with duplicated ID: " + str(self.d_cs_msg))

            return False # we will push extauth request after we update it with thread response
        elif prev_msg and prev_msg['csmsgclass']==CSLogMessageType.ServerResponce \
                and (prev_msg['method']=='MSGCFG_CLIENTREGISTERED' or prev_msg['method']=='MSGCFG_AUTHENTICATED' or prev_msg['method']=='MSGCFG_ERROR'):
            return True # push this (updated) internal message together with final server responce


    def process_exta_accept_message(self):
        # check currently processed
        reqid_exta = self.d_cs_msg['vararg0']  # store reference id  of mf_auth module request
        if reqid_exta in  self.d_cs_exta_msgs:
            readt = self.d_cs_msg['@timestamp']
            self.d_cs_exta_msgs[reqid_exta]['is_failed'] =0
            reqdt = self.d_cs_exta_msgs[reqid_exta]['@timestamp']
            dtdiff = readt - reqdt
            msdelta = int(dtdiff.total_seconds() * 1000)
            self.d_cs_exta_msgs[reqid_exta]['duration_accept_exta'] = msdelta

        return False # accept messages should be discarded (will push updated exta reques entry when we process final responce)


    def process_exta_initconn_message(self):
        ldap_target = self.d_cs_msg['vararg0'].rstrip('.')  # store target server:port

        if not ldap_target in self.d_cs_exta_intops:
            self.d_cs_exta_intops[ldap_target] = {}
        self.d_cs_msg['method'] = 'LDAP_INIT'
        self.d_cs_msg['is_failed'] = -1  # not accepted yet
        self.d_cs_msg['duration_accept_exta'] = 0
        self.d_cs_msg['conn_type_exta'] = None
        # we cannot distinguish between several init connection attempts, we assume extmodule always re-establish
        # only one connection at a time
        if not CSLogMessageType.ExtAuthInitConnection in self.d_cs_exta_intops[ldap_target]:
            self.d_cs_exta_intops[ldap_target][CSLogMessageType.ExtAuthInitConnection] = self.d_cs_msg
        else:
            if self.d_cs_exta_intops[ldap_target][CSLogMessageType.ExtAuthInitConnection]['is_failed'] != 0:
                curr_msg = self.d_cs_msg
                self.d_cs_msg = self.d_cs_exta_intops[ldap_target][CSLogMessageType.ExtAuthInitConnection]
                self.d_cs_exta_intops[ldap_target][CSLogMessageType.ExtAuthInitConnection] = curr_msg
                return True # previos connection was not accepted, push it as current message and swap to new in hash
            else:
                self.d_cs_exta_intops[ldap_target][CSLogMessageType.ExtAuthInitConnection] =self.d_cs_msg

        return False  # we will push extauth operation after we update it with responce

    def process_exta_acceptconn_message(self):
        conn_type_id = self.d_cs_msg['vararg0']
        # scan all non-committed connections and check that type of non-committed conn match (SEARCH==SEARCH)
        # or type of non-commited connection is unknown and our  type is BIND
        for endpoint in self.d_cs_exta_intops:
            if CSLogMessageType.ExtAuthInitConnection in self.d_cs_exta_intops[endpoint]:
                msg_candidate =self.d_cs_exta_intops[endpoint][CSLogMessageType.ExtAuthInitConnection]
                is_matched = False
                if msg_candidate['is_failed'] == -1:
                    if (not msg_candidate['conn_type_exta']) and (conn_type_id == '2'): # BIND connection
                        msg_candidate['is_failed'] = 0
                        msg_candidate['conn_type_exta'] = 'BIND'
                        is_matched = True
                    elif (msg_candidate['conn_type_exta'] == 'SEARCH') and (conn_type_id == '1'): # SEARCH connection
                        msg_candidate['is_failed'] = 0
                        msg_candidate['conn_type_exta'] = 'SEARCH'
                        is_matched = True
                    if is_matched:
                        # extract and submit original conection message, discard this one
                        reqdt = msg_candidate['@timestamp']
                        resdt = self.d_cs_msg['@timestamp']
                        dtdiff = resdt - reqdt
                        msdelta = int(dtdiff.total_seconds() * 1000)
                        self.d_cs_msg = msg_candidate.copy()
                        self.d_cs_msg['duration_accept_exta'] = msdelta
                        del self.d_cs_exta_intops[endpoint][CSLogMessageType.ExtAuthInitConnection]
                        return True  # responce has been updated, push self.d_cs_msg to submiter
        logging.info("Ignored exta connection establishment (no match): " + str(self.d_cs_msg))

        return False

    def process_exta_bind_message(self):
        reqid_exta = self.d_cs_msg['vararg0']
        if reqid_exta == '-1':  # this is administrative bind for search connection
            endpoint = self.d_cs_msg['vararg2']
            if endpoint in self.d_cs_exta_intops:
                if CSLogMessageType.ExtAuthInitConnection in self.d_cs_exta_intops[endpoint]:
                    msg_candidate = self.d_cs_exta_intops[endpoint][CSLogMessageType.ExtAuthInitConnection]
                    if (msg_candidate['is_failed'] == -1) and (not msg_candidate['conn_type_exta']):
                        msg_candidate['conn_type_exta'] = 'SEARCH'
                        return False # todo, maybe calculate duration in case we wont get final conenction init?
            logging.info("exta Administrative BIND (no match): " + str(self.d_cs_msg))
            self.d_cs_msg['reqid_exta'] =-1
            self.d_cs_msg['reqid'] = -1
            self.d_cs_msg['method']= 'LDAP_BIND'
            return True # we report any of such messages as is
        elif reqid_exta in self.d_cs_exta_msgs:
            reqid = self.d_cs_exta_msgs[reqid_exta]['reqid']
            self.d_cs_msg['reqid_exta'] =reqid_exta
            self.d_cs_msg['reqid'] = reqid
            self.d_cs_msg['method'] = 'LDAP_BIND'
            return True

    def process_exta_connclosed_message(self):
        endpoint = self.d_cs_msg['vararg0']
        if endpoint in self.d_cs_exta_intops:
            if CSLogMessageType.ExtAuthInitConnection in self.d_cs_exta_intops[endpoint]:
                conn_inited = self.d_cs_exta_intops[endpoint][CSLogMessageType.ExtAuthInitConnection]
                if conn_inited['is_failed'] == -1 and (not conn_inited['conn_type_exta']  or conn_inited['conn_type_exta'] == 'SEARCH'):
                    # if we see disconnect from endpoint while we have pending SEARCH or unknown conenction then it is LIKELY this connection error
                    conn_inited['is_failed'] = 1
                    # extract and submit original conection message, discard this one
                    reqdt = conn_inited['@timestamp']
                    resdt = self.d_cs_msg['@timestamp']
                    dtdiff = resdt - reqdt
                    msdelta = int(dtdiff.total_seconds() * 1000)
                    self.d_cs_msg = conn_inited.copy()
                    self.d_cs_msg['duration_accept_exta'] = msdelta
                    del self.d_cs_exta_intops[endpoint][CSLogMessageType.ExtAuthInitConnection]
                    return True  # responce has been updated, push self.d_cs_msg to submiter
        if self.d_cs_msg['vararg1']=='1':
            self.d_cs_msg['conn_type_exta'] =  'SEARCH'
        else:
            self.d_cs_msg['conn_type_exta'] = 'BIND'
        self.d_cs_msg['conn_state'] =  self.d_cs_msg['vararg2']
        self.d_cs_msg['method'] = 'LDAP_CLOSE'
        return True


    def process_cs_responce_message(self):
        lines = self.cs_msg.splitlines(1);
        if len(lines) > 0 and lines[0]:
            tokens = lines[0].split();
            if len(tokens) >= 7:
                clientid = tokens[6]
                pc = self.cs_msg.find("IATRCFG_REQUESTID")
                if pc != -1:
                    pce = self.cs_msg.find('\n', pc + 37) # len("IATRCFG_ERRORCODE           value:   ")
                    refid = self.cs_msg[pc + 37:pce]
                    method = CSLogMessageType.ClientRequest;
                    ''' Check if request exists in pool '''
                    reqfound = False
                    if clientid in self.d_cs_clients_msgs:
                        if refid in self.d_cs_clients_msgs[clientid]:
                            if method in self.d_cs_clients_msgs[clientid][refid]:
                                clientreqmsg = self.d_cs_clients_msgs[clientid][refid][method]
                                reqdt = clientreqmsg['@timestamp']
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

                                # check if this is error message or regular responce
                                if self.d_cs_msg['method'] == 'MSGCFG_ERROR':
                                    clientreqmsg['is_failed'] = 1
                                    pc = self.cs_msg.find("IATRCFG_ERRORCODE")
                                    if pc != -1:
                                        pce = self.cs_msg.find('\n', pc + 37)
                                        clientreqmsg['error_code'] = self.cs_msg[pc + 37:pce]
                                    else:
                                        clientreqmsg['error_code'] = -1
                                    pc = self.cs_msg.find("SATRCFG_DESCRIPTION")
                                    if pc != -1:
                                        pce = self.cs_msg.find('\n', pc + 37)
                                        clientreqmsg['error_description'] = self.cs_msg[pc + 37:pce]
                                    else:
                                        clientreqmsg['error_description'] = ''
                                else:
                                    clientreqmsg['is_failed'] = 0
                                    clientreqmsg['error_code'] = 0
                                    clientreqmsg['error_description'] = ''


                                    # check if we have any pending exta requests associated with this client request and push them first
                                if CSLogMessageType.ExtAuthRequest in self.d_cs_clients_msgs[clientid][refid]:
                                    prev_msg = next(iter(self.d_cs_msg_stack or []), None)
                                    if prev_msg:
                                        self.d_cs_msg_stack.pop(0)
                                    self.d_cs_msg_stack.append(self.d_cs_msg)
                                    self.d_cs_msg = self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ExtAuthRequest].copy()
                                    del self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ExtAuthRequest]
                                    if self.d_cs_msg['reqid_exta'] in self.d_cs_exta_msgs:
                                        del self.d_cs_exta_msgs[self.d_cs_msg['reqid_exta']]
                                    if not 'accept_exta' in self.d_cs_msg:
                                        self.d_cs_msg['is_failed'] ='1'  # never accepted by module
                                        self.d_cs_msg['duration_accept_exta'] = msdelta # duration of ext auth attempt is duration of entire client request

                                    curr_cs_msg = self.cs_msg;
                                    self.cs_msg = None
                                    self.submit_cs_message()
                                    self.in_cs_msg = 1
                                    self.cs_msg = curr_cs_msg
                                    self.d_cs_msg_stack.pop(0)
                                    if prev_msg:
                                        self.d_cs_msg_stack.append(prev_msg)

                                # push this client message out as usuall
                                self.d_cs_msg = clientreqmsg.copy()
                                self.d_cs_msg['duration'] = msdelta
                                del self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest]
                                #TODO: check if we have other abandoned internal messages associated with this id
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
                        if CSLogMessageType.ClientRequest in self.d_cs_clients_msgs[clientid][refid] and \
                                self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest]['method']:
                            m = self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest]['method']
                            if (m.startswith("MSGCFG_GETOBJECT") or
                                m.startswith("MSGCFG_GETBRIEF")):
                                    is_request_found = True
                                    self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest]['objcntr'] = num
                                    self.d_cs_clients_msgs[clientid][refid][CSLogMessageType.ClientRequest]['objtype'] = sobj

                if (not is_request_found):
                    logging.info("Ingnored detail message (no match): " +str(self.d_cs_msg) )

        return False # result message shoudl be discarded (will push updated entry when we process final responce msg)



    def __del__(self):
        logging.debug("SIPSMsgParser __del__")
        self.in_shutdown = True
        if(self.in_cs_msg):
            self.submit_cs_message()
        # go through all caches and submit unprocessed messages as-is
        # clients/requests cache
        for clientid in self.d_cs_clients_msgs:
            for refid in self.d_cs_clients_msgs[clientid]:
                for typeid in self.d_cs_clients_msgs[clientid][refid]:
                    self.d_cs_msg = self.d_cs_clients_msgs[clientid][refid][typeid]
                    self.d_cs_msg['is_failed'] = -1 # we dont know, no information in log
                    self.submit_cs_message()
        #external auth messages
        for endpoint in self.d_cs_exta_intops:
            for typeid in self.d_cs_exta_intops[endpoint]:
                self.d_cs_msg =self.d_cs_exta_intops[endpoint][typeid]
                self.d_cs_msg['is_failed'] = -1  # we dont know, no information in log
                self.submit_cs_message()

        LogParser.__del__(self)
        return