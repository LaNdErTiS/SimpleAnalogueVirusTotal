import pickle


class WMIProcessInfo:
    imported_fields = ['ProcessId', 'ParentProcessId', 'Name', 'CommandLine', 'CreationClassName', 'ExecutablePath']

    def __init__(self, proc):
        for field in self.imported_fields:
            setattr(self, field, getattr(proc, field, None))


class ProcessInformation:
    def __init__(self):
        self.pid = None
        self.ppid = None
        self.name = None
        self.cmd_line = None
        self.exe_path = None

        self.connections = []
        self.memory = []

        self.packer = None
        self.signature_verification = None
        self.section_rights = None
        self.mitre_techniques = []

        self.score = 0

    def __str__(self) -> str:
        return '<Process>\n' \
               f'PID = {self.pid}\n' \
               f'Name = {self.name}\n' \
               f'Exe_Path = {self.exe_path}\n' \
               f'Packer = {self.packer}\n' \
               f'Sig - {self.signature_verification}\n' \
               f'Section rights - {self.section_rights}\n' \
               f'Connections - {self.connections}' \
               f'Score - {self.score}'

    def init(self, source: WMIProcessInfo):
        self.pid = source.ProcessId
        self.ppid = source.ParentProcessId
        self.name = source.Name
        self.cmd_line = source.CommandLine
        self.exe_path = source.ExecutablePath

    def json(self):
        import scoring
        packer = self.packer[0] if len(self.packer) > 0 else None
        signature = self.signature_verification[0] if len(self.signature_verification) > 0 else None
        sections = pickle.loads(self.section_rights[0]) if len(self.section_rights) > 0 else None
        mitre_techniques = pickle.loads(self.mitre_techniques[0]) if len(self.mitre_techniques) > 0 else None

        return {
            'pid': self.pid,
            'ppid': self.ppid,
            'name': self.name,
            'score': scoring.get_score(self),
            'cmd_line': self.cmd_line,
            'exe_path': self.exe_path,
            'packer': packer if packer else 'unknown',
            'signature': str(signature) if signature else 'unknown',
            'sections_rights': ([{'section': section_name, 'rights': sections[section_name]} for section_name
                                 in sections] if sections else []),
            'mitre_techniques': (mitre_techniques if mitre_techniques else []),
            'connections': [conn.json() for conn in self.connections],
            'memory_check': pickle.loads(self.memory[0]) if len(self.memory) > 0 else None
        }
