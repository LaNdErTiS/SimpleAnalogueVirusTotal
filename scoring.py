from data_types.process_info import ProcessInformation
from signify.authenticode import AuthenticodeVerificationResult
import enum
import pickle


class ScoreClass(enum.Enum):
    CLEAN = 0,
    SUSPICIOUS = 1,
    HIGHLY_SUSPICIOUS = 2
    MALICIOUS = 3

    def __rt__(self, other):
        if type(self) == type(other):
            return self.value > other.value


def get_process_score_class(proc: ProcessInformation) -> ScoreClass:
    if proc.score >= 75:
        return ScoreClass.MALICIOUS
    elif proc.score >= 50:
        return ScoreClass.HIGHLY_SUSPICIOUS
    elif proc.score >= 25:
        return ScoreClass.SUSPICIOUS
    else:
        return ScoreClass.CLEAN


# score +10 if True else +0
def is_malware_packer_used(packer: str) -> dict:
    # Top 10 popular packers used in malware
    if not packer:
        return {'score_impact': 0}
    packer = packer.lower()
    packers = ["upx", "enigma", "exestealth", "morphine", "themida", "fsg", "pespin", "vmprotect", "obsidium", "mew"]
    for packer_iter in packers:
        if packer.find(packer_iter) != -1:
            return {'score_impact': 10, 'reason': 'malicious_packer', 'data': packer_iter}

    return {'score_impact': 0}


# score +10 if True else +0
def is_malware_pe_file_signature(result_code: AuthenticodeVerificationResult) -> dict:
    if not result_code:
        return {'score_impact': 0}
    if result_code != AuthenticodeVerificationResult.OK and result_code != AuthenticodeVerificationResult.NOT_SIGNED:
        return {'score_impact': 10, 'reason': 'bad_signature', 'data': str(result_code)}

    return {'score_impact': 0}


# score +10 for each section if True else +0
def is_malware_sections_attributes(sections: dict) -> dict:
    if not sections:
        return {'score_impact': 0}
    malware_rights = ['IMAGE_SCN_MEM_EXECUTE', 'IMAGE_SCN_MEM_WRITE']

    bad_section_count = 0
    section_names = []

    for i in sections.keys():
        section_right = sections[i]
        flag = True
        for j in malware_rights:
            if j not in section_right:
                flag = False
                break

        if flag:
            bad_section_count += 1
            section_names.append(i)

    return {'score_impact': bad_section_count * 10, 'reason': 'malicious_section_rights', 'data': section_names}


SCORE_THRESHOLD = 40


def score_connections(process: ProcessInformation) -> dict:
    score = 0
    mal_conn = None
    for conn in process.connections:
        if conn.abuseScore > score:
            score = conn.abuseScore
            mal_conn = conn
    if score >= SCORE_THRESHOLD:
        return {'score_impact': score, 'reason': 'malicious_connection', 'data': mal_conn.json()}

    return {'score_impact': 0}


def score_dynamic_section_data(process: ProcessInformation):
    mem = pickle.loads(process.memory[0]) if len(process.memory) > 0 else None
    if mem is None:
        return {'score_impact': 0}

    score = 0
    data = []
    for k, sections in mem.items():
        for section in sections.keys():
            res = sections[section]['result']
            if res.lower() == 'ok':
                continue
            reasons = sections[section]['reasons']

            for reason in reasons:
                if reason['reason'] == 'unequal_section_size':
                    pe = int(reason['data']['pe'], base=16)
                    mem = int(reason['data']['mem'], base=16)
                    if abs(mem - pe) > 0x1000:
                        data.append(
                            {'section': section, 'reason': 'high_size_diff', 'diff': f'0x{abs(mem - pe):X}'})
                        score += 10
                elif reason['reason'] == 'unmatching_bytes':
                    data.append({'section': section, 'reason': 'unmatching_bytes'})
                    score += 20
    if score > 0:
        return {'score_impact': score, 'reason': 'bad_sections_data', 'data': data}

    return {'score_impact': 0}


def get_mitre_score(process: ProcessInformation):
    mitre_techniques = pickle.loads(process.mitre_techniques[0]) if len(process.mitre_techniques) > 0 else []
    score = 5 * len(mitre_techniques)

    if score > 0:
        return {'score_impact': score, 'reason': 'mitre_techniques'}
    return {'score_impact': score}


def get_score(process: ProcessInformation):
    total_score = 0
    total_impacts = []
    if len(process.packer) > 0:
        impact = is_malware_packer_used(process.packer[0])
        if impact['score_impact'] != 0:
            total_score += impact['score_impact']
            total_impacts.append(impact)

    if len(process.signature_verification) > 0:
        impact = is_malware_pe_file_signature(process.signature_verification[0])
        if impact['score_impact'] != 0:
            total_score += impact['score_impact']
            total_impacts.append(impact)

    if len(process.section_rights) > 0:
        impact = is_malware_sections_attributes(pickle.loads(process.section_rights[0]))
        if impact['score_impact'] != 0:
            total_score += impact['score_impact']
            total_impacts.append(impact)

    impact = score_connections(process)
    if impact['score_impact'] != 0:
        total_score += impact['score_impact']
        total_impacts.append(impact)

    impact = score_dynamic_section_data(process)
    if impact['score_impact'] != 0:
        total_score += impact['score_impact']
        total_impacts.append(impact)

    impact = get_mitre_score(process)
    if impact['score_impact'] != 0:
        total_score += impact['score_impact']
        total_impacts.append(impact)

    result = {'total_score': total_score}
    if total_score > 0:
        result['reasons'] = total_impacts

    return result
