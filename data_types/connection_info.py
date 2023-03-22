import requests

ABUSEIPDB_KEY = r'ed0b0c022abc6bc460128d5b2901b2c0d9fc46ecfd94d9e410d78bca69050f179c3b908ed03ea2ab'
ABUSEIPDB_REQUEST = 'https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90'


class ConnectionInfo:

    def __init__(self, conn):
        self.domain = None
        self.isp = None
        self.usageType = None
        self.countryCode = None
        self.abuseScore = None
        self.pid = conn.pid
        self.laddr = conn.laddr
        self.raddr = conn.raddr
        self.family = conn.family

    def __str__(self):
        laddr_port = f'{self.laddr[0]} {f":{self.laddr[1]}" if len(self.laddr) > 1 else ""}' if len(
            self.laddr) > 0 else ''
        raddr_port = f'{self.raddr[0]} {f":{self.raddr[1]}" if len(self.raddr) > 1 else ""}' if len(
            self.raddr) > 0 else ''
        return f'[{self.pid}] {laddr_port} -> {raddr_port} - {self.isp}, {self.countryCode} SCORE: {self.abuseScore}'

    def retrieve_info(self):
        if not self.raddr:
            return False

        try:
            ip = self.raddr[0]

            headers = {
                'Key': ABUSEIPDB_KEY,
                'Accept': 'application/json'
            }
            response = requests.get(ABUSEIPDB_REQUEST.format(ip=ip), headers=headers)
            ip_info = response.json()["data"]

            self.abuseScore = ip_info["abuseConfidenceScore"]
            self.countryCode = ip_info["countryCode"]
            self.usageType = ip_info["usageType"]
            self.isp = ip_info["isp"]
            self.domain = ip_info["domain"]
        except Exception as e:
            pass

    def json(self):
        _from = {}
        if len(self.laddr) > 0:
            _from['ip'] = self.laddr[0]
        if len(self.laddr) > 1:
            _from['port'] = self.laddr[1]

        _to = {}
        if len(self.raddr) > 0:
            _to['ip'] = self.raddr[0]
        if len(self.raddr) > 1:
            _to['port'] = self.raddr[1]

        res = {
            'from': _from,
            'to': _to
        }

        if self.domain:
            res['domain'] = self.domain
            res['country'] = self.countryCode
            res['usageType'] = self.usageType
            res['isp'] = self.isp
            res['abuseScore'] = self.abuseScore

        return res
