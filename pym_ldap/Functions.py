import subprocess
import os
import pym_logger as logger

log = logger.get_logger(__name__)


def grant_write_property_access(object_dn: str, netbios_login: str, property_name: str, server: str = None):
    prog_path = get_dsacls_path()
    if server:
        ldap_object_path = f'"\\\\{server}\\{object_dn}"'
    else:
        ldap_object_path = f'"{object_dn}"'
    grantee_arg = f"{netbios_login}:WP;{property_name};"
    cmd = " ".join([prog_path, ldap_object_path, "/G", grantee_arg])
    result = exec_win_cmd(command=cmd)
    if result == 0:
        return True
    else:
        return False


def reset_ldap_object_access(object_dn: str, server: str = None):
    prog_path = get_dsacls_path()
    if server:
        ldap_object_path = f'"\\\\{server}\\{object_dn}"'
    else:
        ldap_object_path = f'"{object_dn}"'
    cmd = " ".join([prog_path, ldap_object_path, "/resetDefaultDACL"])
    result = exec_win_cmd(command=cmd)
    if result == 0:
        return True
    else:
        return False


def exec_win_cmd(command: str) -> int:
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="cp866", shell=True)
    log.debug(f"Выполнение команды windows cmd {command}")
    result = process.communicate()
    output = result[0]
    errors = result[1]
    if errors != "":
        log.warning(errors)
    log.debug(output)
    return process.returncode


def get_dsacls_path() -> str:
    current_dir = os.path.dirname(__file__)
    prog_path = os.path.join(current_dir, "exec", "dsacls")
    prog_path = os.path.join(prog_path, "dsacls.exe")
    return f'"{prog_path}"'
