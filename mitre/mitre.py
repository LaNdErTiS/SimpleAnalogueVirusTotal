import os
import yara
from mitre.yarascan import YaraScan, process_file


def get_mitre_techniques(path_exe: str) -> dict:
    yara_scan = YaraScan()
    mitre_file = os.path.join(os.getcwd(), 'mitre\\mitre.yar')

    yara_mitre_rules = yara.compile(mitre_file)

    return process_file(yara_scan, yara_mitre_rules, path_exe, '')

# if __name__ == "__main__":
#     filename = "rufus-3.15.exe"
#     yara_scan = YaraScan()
#     yara_mitre_rules = yara.compile('./mitre1.yar')
#     dst_dir = "C:\\Users\\LanDe\\Desktop"
#     dst_file_static = os.path.join(dst_dir, filename) + ".yara.json"
#     dst_file_mitre = os.path.join(dst_dir, filename) + ".mitre.json"
#     src_file = os.path.join("C:\\Users\\LanDe\\Desktop", filename)
#
#     process_file(yara_scan, yara_mitre_rules, src_file, dst_file_mitre)
