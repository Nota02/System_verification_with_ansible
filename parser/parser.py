import os
import json
import re


class BaseParser:
    logs = []

    def __init__(self, path):
        self.path = path
        self.markdown_dict = {}
        self.markdown = f'# {self.path} \n\n'
        try:
            with open(path, "r", encoding='utf-8', errors='ignore') as log:
                self.log = log.read()
                print(path)
        except:
            pass

        BaseParser.logs.append(self)

    def pars(self, path):
        self.__class__.logs.append(self)

    def make_md(self):
        pass

    @classmethod
    def compile(cls, path):
        result = ""
        for pars in cls.logs:
            pars.pars()
            pars.make_md()
            result += pars.markdown
        with open(os.path.join(path + 'result.md'), 'w', encoding="utf-8") as file:
            file.write(result)


class GrypeParser(BaseParser):
    def pars(self):
        convertedDict = json.loads(self.log)
        self.markdown_dict = {}
        for key in convertedDict.keys():
            if key == "source":
                self.markdown_dict[key] = {
                    "type": convertedDict[key]["type"],
                    "target": {
                        "userInput": convertedDict[key]["target"]["userInput"],
                        "mediaType": convertedDict[key]["target"]["mediaType"],
                    }
                }
            elif key == "matches":
                self.markdown_dict[key] = []
                for ele in convertedDict[key]:
                    self.markdown_dict[key].append([])
                    self.markdown_dict[key][-1].append(ele["vulnerability"]["severity"])
                    try:
                        self.markdown_dict[key][-1].append(ele["vulnerability"]["description"])
                    except:
                        self.markdown_dict[key][-1].append("")
                    self.markdown_dict[key][-1].append(ele["vulnerability"]["fix"]["state"])

    def make_md(self):
        self.markdown += f"##  Type: __{self.markdown_dict['source']['type']}__\n\n"
        self.markdown += f"##  userInput: __{self.markdown_dict['source']['target']['userInput']}__\n\n"
        self.markdown += f"### __{self.markdown_dict['source']['target']['mediaType']}__\n\n"
        for ele in self.markdown_dict["matches"]:
            if ele[0] in ['High', 'Critical']:
                self.markdown += "> **" + ele[0] + "** ``" + ele[2] + "``" + \
                                 ele[1] + "\n" * 2
            else:
                self.markdown += "> *" + ele[0] + "* ``" + ele[2] + "``" + \
                                 ele[1] + "\n" * 2


class LinPeasParser(BaseParser):
    regex_filter = r'\[[\d;]+m'
    # regex_headers = r"в•”в(•ђв)+•—\nв(•ђв)+•Ј\s\w+\s\w+\sв• в(•ђв)+•ђ\n\s+в•љв(•ђв)+•ќ"
    regex_headers = r"╔═+╗\n═+╣\s\w+\s\w+\s╠═+\n\s+╚═+╝"

    def pars(self):
        self.markdown_dict = self.log
        for match in re.finditer(self.regex_filter, self.log, re.MULTILINE):
            self.markdown_dict = self.markdown_dict.replace(match.group(0), "")

    def make_md(self):
        self.markdown += self.markdown_dict


class KubsParser(BaseParser):
    regex_summary = r'==\sSummary\s\w+\s==\n(.+\n){4}'
    regex_summary_deteils = r'(\d+)\s(checks)\s(\w{4})'
    regex_remediations = r'==\sRemediations\s\w+\s==((\n|.)+)'
    regex_remediations_log = r'(\d(\.\d(\.\d+)))\s'
    regex_log = r'\[(\w{4})\]\s(\d(\.\d(\.\d+)?)?)\s(.+)'

    def pars(self):
        last = 0
        self.markdown_dict = []
        for match_summary in re.finditer(self.regex_summary, self.log, re.MULTILINE):
            self.markdown_dict.append({'logs': [], 'remediations': [], 'summary': []})
            part = self.log[last:match_summary.start()]
            for match_remediations in re.finditer(self.regex_remediations, part, re.MULTILINE):
                logs = part[:match_remediations.start()]
                for match_log in re.finditer(self.regex_log, logs, re.MULTILINE):
                    self.markdown_dict[-1]['logs'].append([match_log.group(1), match_log.group(2), match_log.group(5)])
                remediations = match_remediations.group(1)
                last_remediation = 0
                for match_remediations_log in re.finditer(self.regex_remediations_log, remediations, re.MULTILINE):
                    remediation_num = match_remediations_log.group(1)
                    self.markdown_dict[-1]['remediations'].append([remediation_num, ])
                    if last_remediation:
                        remediation = remediations[last_remediation:match_remediations_log.start()].replace('\n\n',
                                                                                                            '\n')
                        self.markdown_dict[-1]['remediations'][-2].append(remediation)
                    last_remediation = match_remediations_log.end()
                self.markdown_dict[-1]['remediations'][-1].append(
                    remediations[match_remediations_log.end():].replace('\n\n', '\n'))

            match_summary.start()
            for match_summary_deteils in re.finditer(self.regex_summary_deteils, match_summary.group(0), re.MULTILINE):
                self.markdown_dict[-1]['summary'].append(
                    [match_summary_deteils.group(1), match_summary_deteils.group(2), match_summary_deteils.group(3)])
            last = match_summary.end()

    def make_md(self):
        if self.markdown_dict:
            for ele in self.markdown_dict:
                if isinstance(ele, dict):
                    for key_item, value_item in ele.items():
                        if value_item:
                            self.markdown += "## " + key_item + "\n" * 2
                        if key_item == 'logs':
                            for value in value_item:
                                if value[0] == 'WARN':
                                    self.markdown += "> **" + value[0] + "** ``" + value[1] + "``" + \
                                                     value[2] + "\n" * 2
                                else:
                                    self.markdown += "> *" + value[0] + "* ``" + value[1] + "``" + \
                                                     value[2] + "\n" * 2
                        if key_item == 'remediations':
                            for value in value_item:
                                self.markdown += "> ``" + value[0] + "``" + \
                                                 value[1] + "\n" * 2
                        if key_item == 'summary':
                            for value in value_item:
                                self.markdown += "> ``" + value[0] + "``" + \
                                                 value[1] + " *" + value[2] + "*" + "\n" * 2


class DockerParser(BaseParser):
    regex_init = r"(Initializing) (\d+[-:T+]?)+"
    regex_section = [r"\[\d+;\d+m(Section\s\w\s-\s.+)\[\d+m\n\n((.|\n)+\n\n\n)",
                     r"\[\d+;\d+m(Section\s\w\s-\s.+)\[\d+m\n\n((.|\n)+\n\n)"]
    regex_details = [r"(\[\d+;\d+m\[(\w+)\]\[\d+m ([\s\d\w\.\:]+)\s+(.+)\n)",
                     r"\[\d+;\d+m\[(\w+)\]\[\d+m ([\s\d\w\.\:]+)\n"]

    def pars(self):
        if self.log:
            log = self.log
            self.markdown_dict['Initializing'] = list(re.finditer(self.__class__.regex_init, log, re.MULTILINE))[0][0]
            log = (log[len(self.markdown_dict['Initializing']):])
            self.markdown_dict['Sections'] = []
            for ends in range(0, 2):
                for section in re.finditer(self.__class__.regex_section[ends], log, re.MULTILINE):
                    self.markdown_dict['Sections'].append({'Section_title': section.group(1)})
                    self.markdown_dict['Sections'][-1]['Events'] = []
                    for events in re.finditer(self.__class__.regex_details[ends], section.group(2), re.MULTILINE):
                        self.markdown_dict['Sections'][-1]['Events'].append(list(events.groups())[1:4])
                    log = log[len(section.group(0)):]
            del log

    def make_md(self):
        if self.markdown_dict:
            for ele in self.markdown_dict.values():
                if isinstance(ele, str):
                    self.markdown += "## " + ele + "\n" * 2
                elif isinstance(ele, list):
                    for sub_item in ele:
                        if isinstance(sub_item, dict):
                            for sub_ele in sub_item.values():
                                if isinstance(sub_ele, str):
                                    self.markdown += "### " + sub_ele + "\n" * 2
                                elif isinstance(sub_ele, list):
                                    for sub_str in sub_ele:
                                        if len(sub_str) == 3:
                                            if sub_str[0] == 'WARN':
                                                self.markdown += "> **" + sub_str[0] + "** ``" + sub_str[1] + "``" + \
                                                                 sub_str[2] + "\n" * 2
                                            else:
                                                self.markdown += "> *" + sub_str[0] + "* ``" + sub_str[1] + "``" + \
                                                                 sub_str[2] + "\n" * 2
                                        else:
                                            self.markdown += "> " + " ".join(sub_str) + "\n" * 2
