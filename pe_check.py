import pefile
import peid
import hashlib
import requests
from signify.authenticode import SignedPEFile, AuthenticodeVerificationResult


def get_packer(path_exe: str) -> str:
    packer = peid.identify_packer(path_exe, db=peid.DB)
    return packer


def get_pe_file_signature(path_exe: str) -> AuthenticodeVerificationResult:
    with open(path_exe, "rb") as f:
        pe_file = SignedPEFile(f)
        status, err = pe_file.explain_verify()

        return status


def get_sections_attributes(path_exe: str) -> dict:
    flags = {}
    pe = pefile.PE(path_exe)
    section_flags = pefile.retrieve_flags(pefile.SECTION_CHARACTERISTICS, "IMAGE_SCN_")
    for section in pe.sections:
        sec_name = section.Name.decode("utf-8")
        flags[(sec_name.strip('\x00'))] = None
        local_flags = []
        for flag in section_flags:
            if getattr(section, flag[0]):
                local_flags.append(flag[0])

        flags[(sec_name.strip('\x00'))] = local_flags

    return flags


def get_sha_256(path_exe: str) -> str:
    with open(path_exe, "rb") as f:
        bytes = f.read()
        readable_hash = hashlib.sha256(bytes).hexdigest()

    return readable_hash


def get_virus_total_mitre(sha256: str) -> dict:
    url = f'https://www.virustotal.com/api/v3/files/{sha256}/behaviour_mitre_trees'
    headers = {"x-apikey": "d99cb4143816177dbbeeaec7de60bed80d3ebdf097bb7429ffa25cac8edfdab2"}
    return requests.get(url, headers=headers).json()


def get_mitre_techniques(data: dict) -> list:
    techniques = []
    if 'data' not in data:
        return []
    if 'Zenbox' not in data['data']:
        return []
    if 'tactics' not in data['data']['Zenbox']:
        return []

    for i in data["data"]["Zenbox"]["tactics"]:
        for j in i["techniques"]:
            techniques.append(j["name"])

    return list(set(techniques))


def check_mitre(path_exe: str):
    try:
        return get_mitre_techniques(get_virus_total_mitre(get_sha_256(path_exe)))
    except Exception as e:
        return []
