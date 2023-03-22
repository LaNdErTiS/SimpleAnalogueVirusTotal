import yara
import json


class YaraScan:
    def __init__(self):
        self.yara_sig_matched = {}

    def yara_callback_desc(self, data):
        if data['matches']:
            tag = ""
            if len(data['tags']) > 0:
                for tag in data['tags']:
                    if tag not in list(self.yara_sig_matched.keys()):
                        self.yara_sig_matched[tag] = {}
                    if data['rule'] not in list(self.yara_sig_matched[tag].keys()):
                        self.yara_sig_matched[tag][data['rule']] = {}
                        if 'description' in data['meta']:
                            self.yara_sig_matched[tag][data['rule']]['description'] = data['meta']['description']
                        self.yara_sig_matched[tag][data['rule']]['indicators_matched'] = []
                    for string in data['strings']:
                        try:
                            if string[2].decode('windows-1252') \
                                    not in self.yara_sig_matched[tag][data['rule']]['indicators_matched']:
                                self.yara_sig_matched[tag][data['rule']]['indicators_matched']. \
                                    append(string[2].decode('windows-1252'))
                        except:
                            continue
        yara.CALLBACK_CONTINUE


def process_file(yara_scan, yara_mitre_rules, input_file, outputfile_mitre):
    try:
        with open(input_file, 'rb') as f:
            file_data = f.read()

            yara_mitre_rules.match(data=file_data, callback=yara_scan.yara_callback_desc,
                                   which_callbacks=yara.CALLBACK_MATCHES)
            json_data = yara_scan.yara_sig_matched
            # with open(outputfile_mitre, 'w') as fw:
            #     json_report = json.dumps(json_data, sort_keys=True, indent=4)
            #     fw.write(json_report)
            return json_data

    except Exception as e:
        print("Error while parsing for mitre and yara")
        print((str(e)))
