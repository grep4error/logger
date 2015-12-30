import sys
import glob
import StdLibParser
import SIPSMsgParser
import SIPGVPMsgParser
import TLibMsgParser
import Submitter
import eSSubmitter
import CSVPrintSubmitter
import logging
import json
from Submitter import SubmitterError

# returns the file name and the position where parsing shoud resume or begin
# the file name is '' if no path or file found

def get_current_file_and_pos_for_mask(offset_file):
    file_and_pos = ''
    try:
        pos_file = open(offset_file, 'r+')
        file_and_pos = pos_file.readline().split("\t")
        pos_file.close()
    except:
        return ['',0]
    if len(file_and_pos) < 2:
        file_and_pos.append(0)
    else:
        file_and_pos[1] = int(file_and_pos[1])        
    return file_and_pos


def save_current_file_and_pos_for_mask(offset_file,cur_file,cur_pos):
    try:
        pos_file = open(offset_file,'w')
    except:
        return -1
    pos_file.write("%s\t%s" % (cur_file,cur_pos))                
    pos_file.close()


# ------- main part ---------


# debug levels
LOG_LEVELS = {'debug': logging.DEBUG,
              'info': logging.INFO,
              'warning': logging.WARNING,
              'error': logging.ERROR,
              'critical': logging.CRITICAL}  

if len(sys.argv) < 3:
    sys.stderr.write("""Usage python logger.py -f <file mask> -o <offset file> [-parsers stdlib,sips,tlib] 
                      [-submitter [elasticsearch|csv]] [-v debug|info|warning|error|critical] 
                      [-fields @timestamp,field1,field2...] [-tags '{"f1":"v1",...}'] 
                      [-esurl http://somehost:port] [-eschunk n]\n\n
                      this script parses files detecting special messages and outputs them in a variety of ways
                      including CSV and elasticsearch. The last processed file and position are stored in the 
                      offset file, which the script reads at the next run and starts from the saved position,
                      making it possible to process only the information produced since the last run\n\n
                      Command Line Arguments:
                      -f <lile mask>   the path to the log directory and the mask of file, for example
                                       /mnt/log/SIPS/SIPS.????????_??????_???.log
                      -o <offset file> the path and the name of the file where the last processed file name
                                       and the position are stored and used for the next run. Make sure every 
                                       script instance uses its own file
                                       example: /var/tmp/SIPS.txt
                      -parsers <list>  the list of parsers that scan for different message types in the log file
                                       Parsers are executed in the order described in this option
                                       Currently supported parsers are:
                                       stdlib - scans for common lib messages (Std,Trc,Int,Alr)
                                       sips   - scans SIP messages in a SIP Server log
                                       tlib   - scans TLib messages in a TServer(SIP Server) log
                                       sipgvp - scans GVP (RM, MCP) logs for SIP messages
                      -submitter <name> the output type produced by the script, if no value is specified the
                                       script will output filed names and values to stdout
                                       supported values:
                                       elasticsearch - sends messages to elasticsearch in logstash format
                                       csv           - prints message fields in comma-separated format, 
                                                       see -fields attribute for details
                      -fields f1,f2... the list of fields used in CSV output
                      -tags '{json}'   the json-formatted list of additional tags to add to each message
                      -esurl http...   the URL of the elasticsearch cluster, default is http://localhost:9200
                      -eschunk n	   the number of records to submit in one elasticsearch bulk request,
                                       default is 900
                      -format '{json}' formats specigic fields using python .format function, passing field value 
                                       as {}  . In most cases it's not needed as Kibana supports field formatting 
                                       NOT implemented in current version             
                      -v <level>       verbose level - debug|info|warning|error|critical\n
Examples:
 python logger.py -f /Users/sergeyb/Documents/test/midnight/sips_b.*.log -o /Users/sergeyb/Documents/test/midnight/sips.txt \
 -parsers sips -v debug -fields @timestamp,to,from,method,call_id -submitter csv""")
else:


    # read arguments
    cmdline_file_mask    = ''
    cmdline_offset_file  = 'logger_offset.tmp' 
    cmdline_parsers_list = ['stdlib','sips','tlib']
    cmdline_submitter    = 'submitter'
    cmdline_log_level    = 'info'
    cmdline_fields       = ''
    cmdline_tags         = ''
    cmdline_esurl        = 'http://localhost:9200'
    cmdline_eschunk      = 900
    cmdline_formats       = {}
        
    for i in range(len(sys.argv)):
        if(sys.argv[i] == '-f'):
            i = i+1
            cmdline_file_mask = sys.argv[i]
        if(sys.argv[i] == '-o'):
            i = i+1
            cmdline_offset_file = sys.argv[i]
        if(sys.argv[i] == '-parsers'):
            i = i+1
            cmdline_parsers_list = sys.argv[i].split(',')
        if(sys.argv[i] == '-submitter'):
            i = i+1
            cmdline_submitter = sys.argv[i]
        if(sys.argv[i] == '-v'):
            i = i+1
            cmdline_log_level = sys.argv[i]
        if(sys.argv[i] == '-fields'):
            i = i+1
            cmdline_fields = sys.argv[i]
        if(sys.argv[i] == '-tags'):
            i = i+1
            cmdline_tags = json.loads(sys.argv[i])
        if(sys.argv[i] == '-esurl'):
            i = i+1
            cmdline_esurl = sys.argv[i]
        if(sys.argv[i] == '-eschunk'):
            i = i+1
            cmdline_eschunk = int(sys.argv[i])
        if(sys.argv[i] == '-format'):
            i = i+1
            cmdline_formats = json.loads(sys.argv[i])                
            #json_acceptable_string = cmdline_tags.replace("'", "\"")



                
    log_level = LOG_LEVELS.get(cmdline_log_level, logging.NOTSET)
    logging.basicConfig(level=log_level,format=u'%(asctime)s %(name)s %(message)s')

# print parameters
    logging.info("file mask:    " + cmdline_file_mask)
    logging.info("offset file:  " + cmdline_offset_file)        
    logging.info("parsers list: " + str(cmdline_parsers_list))
    logging.info("submitter:    " + cmdline_submitter)             
    logging.info("tags:         " + str(cmdline_tags))
    logging.info("formats:      " + str(cmdline_formats))

# read initial offset from file
    file_and_pos = get_current_file_and_pos_for_mask(cmdline_offset_file)
#    if file_and_pos[0] == '':
#        exit()
    logging.info('starting file and position: '+str(file_and_pos))

# init parser and submitter

    #submitter = Submitter.Submitter(cmdline_fields)
    
    log_parser = []
    
    # SIPPrintSubmitter prints csv SIP massage atteributes
    #     submitter = SIPPrintSubmitter.SIPPrintSubmitter()
    if(cmdline_submitter == 'elasticsearch'):
        logging.debug('submitter set to elasticsearch')
        logging.info("eS URL:       "+cmdline_esurl)
        logging.info("eS bulk size:	"+str(cmdline_eschunk))
        submitter = eSSubmitter.eSSubmitter(cmdline_fields,cmdline_formats,cmdline_esurl,cmdline_eschunk)
    else: 
        if(cmdline_submitter == 'csv'):
            logging.debug('submitter set to csv')
            submitter = CSVPrintSubmitter.CSVPrintSubmitter(cmdline_fields,cmdline_formats)
        else:
            logging.warn('submitter not set, using default')
            submitter = Submitter.Submitter(cmdline_fields,cmdline_formats)
                  
          
    if 'stdlib' in cmdline_parsers_list:
        log_parser.append( StdLibParser.StdLibParser(submitter,tags=cmdline_tags) )
    if 'sips' in cmdline_parsers_list:
        log_parser.append( SIPSMsgParser.SIPSMsgParser(submitter,tags=cmdline_tags) )
    if 'tlib' in cmdline_parsers_list:      
        log_parser.append( TLibMsgParser.TLibMsgParser(submitter,tags=cmdline_tags) )
    if 'sipgvp' in cmdline_parsers_list:      
        log_parser.append( SIPGVPMsgParser.SIPGVPMsgParser(submitter,tags=cmdline_tags) )

# reading files

    file_list = glob.glob(cmdline_file_mask)
    file_list.sort()
    for cur_file_name in file_list:
        if cur_file_name >= file_and_pos[0]:
            logging.info( "reading file name " +cur_file_name)
            cur_file = open(cur_file_name,'r+')
            # add file name to tags
            for parser in log_parser:
                parser.set_file(cur_file_name)
            
            cur_file.seek(file_and_pos[1])
            for line in cur_file:
                #covert to utf8 here?
                
                line_claimed = False
                for parser in log_parser:
                    try:
                        if(line_claimed):
                            parser.parse_line(line.decode('utf-8', 'ignore'),line_claimed)
                        else:    
                            line_claimed = parser.parse_line(line.decode('utf-8', 'ignore'))
                    except SubmitterError:
                        logging.error("ERROR encounted during submit, exiting")
                        save_current_file_and_pos_for_mask(cmdline_offset_file,cur_file_name,cur_file.tell())
                        exit(1)
                    
            logging.info("current file position "+str(cur_file.tell()))     
            save_current_file_and_pos_for_mask(cmdline_offset_file,cur_file_name,cur_file.tell())
            cur_file.close()
            file_and_pos[1] = 0