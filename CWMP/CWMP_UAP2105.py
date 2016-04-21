#!/usr/bin/env python

import asynchat
import asyncore
from collections import deque
import logging
import re
import socket
import random
import copy


logging.basicConfig(level=logging.DEBUG)
SecGWServerAddress = '200.200.200.100'
HNBGwAddress = '10.1.0.10'
HMSAddress = '10.1.0.10'
PLMNID = '90170'


###################### No need to change after this line ######################

try:
    from colorama import init
    init()
    from colorama import Fore, Back, Style

    RED = Fore.RED
    GREEN = Fore.GREEN
    YELLOW = Fore.YELLOW
    RST = Style.RESET_ALL
except ImportError as e:
    RED = ''
    GREEN = ''
    YELLOW = ''
    RST = ''

INT_PORT = 7547

def parse(headers, param):
    return param


def set_parameter_values(data):
    assert isinstance(data, dict)

    result_arr = []

    for key in data:
        result_arr.append((
            '<ParameterValueStruct>'
            '<Name>{0}</Name>'
            '<Value xsi:type="xsd:boolean">{1}</Value>'
            '</ParameterValueStruct>'
        ).format(key, data[key]))

    result = "".join(result_arr)

    result = (
        '<cwmp:SetParameterValues>'
        '<ParameterList soap:arrayType="cwmp:ParameterValueStruct[{0}]">'
        '{1}'
        '</ParameterList>'
        '<ParameterKey>null</ParameterKey>'
        '</cwmp:SetParameterValues>'
    ).format(len(data), result)

    return TEMPLATE.format(result)


TEMPLATE = '''<env:Envelope xmlns:soap-enc="http://schemas.xmlsoap.org/soap/encoding/"
xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema"
xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:cwmp="urn:dslforum-org:cwmp-1-0"><env:Header>
<cwmp:ID env:mustUnderstand="1"></cwmp:ID></env:Header><env:Body>{0}</env:Body></env:Envelope>'''


InformResponse = TEMPLATE.format('''<cwmp:InformResponse><cwmp:HoldRequests>0</cwmp:HoldRequests></cwmp:InformResponse>''')

SetParam_HNBGW = set_parameter_values({
    'configData.FAPService.1.FAPControl.AdminState': 'true',
    'Device.Services.FAPService.1.Transport.X_0D1F7B_FtpServer.Enable': 'true',
    'Device.Services.FAPService.1.FAPControl.UMTS.Gateway.FAPGWServer1': HNBGwAddress,
    'Device.Services.FAPService.1.FaultMgmt.X_0D1F7B_DebugInterface.Oam.MaintainSwitch': 'true',
})

InitialHmsConfiguration = set_parameter_values({
    'Device.Services.FAPService.1.FAPControl.UMTS.Gateway.SecGWServer1': SecGWServerAddress,
    'Device.Services.FAPService.1.FAPControl.UMTS.Gateway.X_0D1F7B_SubnetAddress1': '200.200.200.200',
    'Device.Services.FAPService.1.FAPControl.UMTS.Gateway.X_0D1F7B_SubnetMask1': '255.255.255.0',
    'Device.Services.FAPService.1.FAPControl.UMTS.Gateway.X_0D1F7B_ServiceType1':
        'SIG_CONVERSATIONAL,CLK,INTERACTIVE,STREAMING,BACKGROUND,OM',
    'Device.ManagementServer.URL': 'http://{0}:7547/APHandle'.format(HMSAddress),
})

SetParam_RF = set_parameter_values({
    'Device.Services.FAPService.1.AccessMgmt.X_0D1F7B_LocationBinding.Mode': '0',
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.FDDFAP.RF.PrimaryScramblingCode': '10..12,15',
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.FDDFAP.RF.UARFCNDL': '10562,10566,10569',
    'Device.Services.FAPService.1.REM.X_0D1F7B_MacroCoverageInfoNeeded': 'Optional',
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.FDDFAP.RF.X_0D1F7B_SpecifiedUarfcnPsCode.SpecifiedPsCode': '321',
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.FDDFAP.RF.X_0D1F7B_SpecifiedUarfcnPsCode.SpecifiedUarfcnDl': '123',
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.FDDFAP.RF.X_0D1F7B_SpecifiedUarfcnPsCode.SpecifiedParaEnable': 'false',
})

SetParam_PLMN_LAC = set_parameter_values({
    'Device.Services.FAPService.1.X_0D1F7B_FeatureControl.DiverseSai.DefaultSAC': '255',
    'Device.Services.FAPService.1.CellConfig.UMTS.CN.X_0D1F7B_AirPLMNID': PLMNID,
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.RNCID': '1577',
    'Device.Services.FAPService.1.CellConfig.UMTS.CN.PLMNID': PLMNID,
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.CellID': '33556',
    'Device.Services.FAPService.1.CellConfig.UMTS.CN.LACRAC': '27678:152',
    'Device.Services.FAPService.1.CellConfig.UMTS.CN.SAC': '33556',
    'Device.Services.FAPService.1.X_0D1F7B_FeatureControl.RRCTRLSWITCH.InitUeMessageImsiReportSwitch': 'on',
    'Device.Services.FAPService.1.X_0D1F7B_FeatureControl.RRCTRLSWITCH.CellReselPDPStatusFakeSwitch': 'on',
    'Device.Services.FAPService.1.CellConfig.UMTS.RAN.FDDFAP.CellSelection.UseOfHCS': 'true',
    'Device.Services.FAPService.1.FaultMgmt.X_0D1F7B_DebugInterface.Oam.LocalMaintainSwitch': 'true',
})


class http_request_handler(asynchat.async_chat):
    queue_init = None
    queue_init_orig = deque((InitialHmsConfiguration, ''))
    queue_admin = None
    queue_admin_orig = deque((SetParam_HNBGW, SetParam_RF, SetParam_PLMN_LAC, SetParam_HNBGW, ''))

    def __init__(self, sock, addr, sessions=[], log=None):
        asynchat.async_chat.__init__(self, sock=sock)
        self.addr = addr
        self.sessions = sessions
        self.ibuffer = []
        self.obuffer = ""
        self.headers = {}
        self.set_terminator("\r\n\r\n")
        self.reading_headers = True
        self.handling = False
        self.cgi_data = None
        self.log = log
        self.queue = http_request_handler.queue_init
        self.cwmpid = None
        if not http_request_handler.queue_init:
            http_request_handler.queue_init = copy.copy(http_request_handler.queue_init_orig)
        if not http_request_handler.queue_admin:
            http_request_handler.queue_admin = copy.copy(http_request_handler.queue_admin_orig)

    def collect_incoming_data(self, data):
        logging.debug('%sRecv: %r%s', RED, data, RST)
        self.ibuffer.append(data)

    def parse_headers(self, data):
        data = data.split('\r\n')
        self.op, self.status, self.version = data[0].split(' ')
        headers = data[1:]
        for row in headers:
            row = row.split(':')
            self.headers[row[0].lower()] = row[1].strip()

    def found_terminator(self):
        clen = -1
        if self.reading_headers:
            self.reading_headers = False
            self.parse_headers("".join(self.ibuffer))
            self.ibuffer = []
            if self.op.upper() == "POST":
                clen = int(self.headers["content-length"])
                if clen == 0:
                    self.set_terminator(None)  # browsers sometimes over-send
                    self.cgi_data = parse(self.headers, "".join(self.ibuffer))
                    self.handling = True
                    self.ibuffer = []
                    self.handle_request()
                else:
                    self.set_terminator(int(clen))
            else:
                self.handling = True
                self.set_terminator(None)
                self.handle_request()
        elif not self.handling:
            self.set_terminator(None) # browsers sometimes over-send
            self.cgi_data = parse(self.headers, "".join(self.ibuffer))
            self.handling = True
            self.ibuffer = []
            self.handle_request()

    def handle_request(self):
        logging.info('%sConfig data: %s%s', YELLOW, self.cgi_data.replace('<ParameterValueStruct>', '\n'), RST)

        if 'APHandle' in self.status:
            self.queue = http_request_handler.queue_admin
        elif 'initial_hms' in self.status:
            self.queue = http_request_handler.queue_init

        if 'cwmp:ID' in self.cgi_data:
            self.cwmpid = re.search(r'<cwmp:ID soap-env:mustUnderstand="1">([^<]+)</cwmp:ID>', self.cgi_data).group(1)
        try:
            if 'Inform' in self.cgi_data:
                self.push_http(InformResponse)
            else:
                if self.queue:
                    self.push_http(self.queue.popleft())
                else:
                    self.push_http("")
            self.close_when_done()
        finally:
            self.cwmpid = ''
        #self.push('HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n')

    def push_http(self, data):
        cookie = ''
        if 'Cookie' not in data:
            cookie = 'Set-Cookie: sessionId=1337\r\n'
        data = data.replace('\r', '').replace('\n', '').replace(
            '<cwmp:ID env:mustUnderstand="1"></cwmp:ID>',
            '<cwmp:ID env:mustUnderstand="1">{0}</cwmp:ID>'.format(
                self.cwmpid if self.cwmpid else random.randint(100000, 10000000)
            )
        )
        self.push('HTTP/1.1 200 OK\r\n{0}Content-Length: {1}\r\n\r\n{2}'.format(cookie, len(data), data))

    def push(self, data):
        logging.debug('%sSent: %r%s', GREEN, data, RST)
        asynchat.async_chat.push(self, data)


class CWMP_listener(asyncore.dispatcher):
    def __init__(self, sock=None):
        asyncore.dispatcher.__init__(self, sock)

        if not sock:
            self.create_socket(socket.AF_INET, socket.SOCK_STREAM)
            self.set_reuse_addr()
            try:
                self.bind(('', INT_PORT))
            except socket.error:
                logging.critical('Port already in use. Trying reusing')
                exit()

            self.listen(5)
            logging.critical('Started listening on port: %s', INT_PORT)

    def handle_accept(self):
        pair = self.accept()

        if pair is not None:
            tmp = http_request_handler(pair[0], pair[1])


if __name__ == '__main__':
    a = CWMP_listener()
    asyncore.loop()
