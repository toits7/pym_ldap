import re


def parse_krb5_conf() -> dict:
    krb5_conf_dict = dict()
    with open('/etc/krb5.conf', 'r') as file:
        line = file.readline()
        current_section = ""
        current_key = ""
        while line:
            conf_string = line.lstrip(' ').rstrip(' ').strip('\t')
            conf_string = re.sub(r'(?m)^ *#.*\n?', '', conf_string)
            if conf_string.startswith('['):
                current_section = conf_string.strip('[]\n')
                current_key = ""
                krb5_conf_dict[current_section] = dict()
            elif '=' in conf_string:
                key = conf_string.split('=')[0].strip()
                value = conf_string.split('=')[1].strip()
                if value == '{':
                    current_key = key
                    krb5_conf_dict[current_section][current_key] = dict()
                else:
                    if current_key == "":
                        krb5_conf_dict[current_section][key] = value
                    else:
                        if not key in krb5_conf_dict[current_section][current_key].keys():
                            krb5_conf_dict[current_section][current_key][key] = list()
                        krb5_conf_dict[current_section][current_key][key].append(value)
            elif '}' in conf_string:
                current_key = ""
            line = file.readline()
    return krb5_conf_dict
