# -*- coding: utf-8 -*-  
import sys
import paramiko
import telnetlib
import socket, select
import re
import pdb
import time
import errno
from utils import split_user, del_list_space, NBdiff


class BasicConnection(object):

    def __init__(self, conn_params, conn_type='telnet', conn_init_terminator=r'> $'):
        self.conn_type = conn_type
        self.conn_init_terminator = conn_init_terminator
        self.base_prompt = ''
        self.read_buf = ''

        if conn_type == 'telnet':
            host = conn_params['host']
            port = conn_params.get('port', 23)
            user = conn_params['username']
            password = conn_params['password']
            self.conn = telnetlib.Telnet(host, port=port)
            index, obj, output = self._read_channel_except(r"Username: $")
            self.write_channel(user.encode('ascii') + b"\n")
            index, obj, output = self._read_channel_except(r"Password: $")
            self.write_channel(password.encode('ascii') + b"\n")
            if not self._conn_initiate_read(r'Username: $'):
                raise ValueError('Username or Password Error')
        elif conn_type == 'ssh':
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(**conn_params)
            self.conn = ssh.get_transport().open_session()
            self.conn.settimeout(5)
            self.conn.get_pty()
            self.conn.invoke_shell()
            self._conn_initiate_read()
        else:
            raise ValueError("Invalid protocol specified")

    def _conn_initiate_read(self, err_list=[]):
        if type(err_list) != list:
            err_list = [err_list]
        except_list = [self.conn_init_terminator] + err_list
        index, obj, output = self._read_channel_except(except_list)
        if index == 0:
            self.base_prompt = output.replace('\r', '').split('\n')[-1].split('>')[0]
            return True
        else:
            return False

    def send_command(self, command, except_list, enter=True):
        command = command.replace('\r', '')
        if enter:
            command = command.rstrip("\n")
            command += str('\n')
        self.write_channel(command)
        index, obj, output = self._read_channel_except(except_list)
        #sys.stdout.write(output)
        return index, obj, output

    def write_channel(self, data):
        data = data.encode('ascii')
        if self.conn_type == 'telnet':
            self.conn.write(data)
        elif self.conn_type == 'ssh':
            self.conn.sendall(data)
        else:
            raise ValueError("Invalid protocol specified")

    def _read_channel_except(self, patterns, timeout=10):
        if type(patterns) != list:
            patterns = [patterns]
        if self.conn_type == 'telnet':
            #index, obj, output = self.conn.expect(patterns, timeout)
            index, obj, output = self.conn.expect(patterns, timeout*100)
            if index == -1:
                raise Exception("Timed-out reading channel, patterns %s not found" % patterns)
            self.read_buf += output
            return index, obj, output
        elif self.conn_type == 'ssh':
            output = str()
            while True:
                try:
                    r, w, e = select.select([self.conn], [], [], timeout)
                except select.error, e:
                    if e[0] == errno.EINTR: 
                        continue
                    else: raise
                if r == [] and w == [] and e == []:
                    new_data = self.conn.recv(10240)
                    #print new_data
                    raise Exception("Timed-out reading channel, patterns %s not found, last data:\n%s" % (patterns,output))
                if self.conn in r:
                    try:
                        new_data = self.conn.recv(10240)
                        if len(new_data) == 0:
                            raise EOFError("Channel stream closed by remote device.")
                        output += new_data.decode('utf-8', 'ignore')
                    except socket.timeout:
                        raise Exception("Timed-out reading channel, data not available.")
                    except e:
                        raise Exception("Got an erro when eading channel: %s", str(e))
                index = 0
                for pattern in patterns:
                    obj = re.search(pattern, output)
                    if obj:
                        self.read_buf += output
                        return index, obj, output
                    index += 1
            raise Exception("Timed-out reading channel, pattern not found in output: {}" .format(pattern))
        else:
            raise ValueError("Invalid protocol specified")

    def close(self):
        if self.conn_type == 'telnet':
            self.conn.close()
        elif self.conn_type == 'ssh':
            self.conn.close()

    def cmd_detail(self):
        return self.read_buf + '\n'

    def clear_cmd_detail(self):
		self.read_buf = ""


class CiscoAsaConnection(BasicConnection):

    prompt_terminator = r'> $'


    def enable(self, enpass):
        super(CiscoAsaConnection, self).send_command("enable", r"Password: $")
        index, obj, text = super(CiscoAsaConnection, self).send_command(enpass,
                [r"# $", r"Password: $"])
        if index == 1:
            raise Exception('Enable password error!')
        self.prompt_terminator = r'# $'

    def config(self):
        super(CiscoAsaConnection, self).send_command("configure terminal",
                [r"\)# $"])
        self.prompt_terminator = r'\)# $'

    def send_command(self, command, err_list=[], enter=True):
        if type(err_list) != list:
            err_list = [err]
        except_list = [self.prompt_terminator] + err_list
        index, obj, text = super(CiscoAsaConnection, self).send_command(command,
                except_list, enter)
        if index == 0:
            err_pattern = None
        else:
            err_pattern = err_list[index - 1]
        return text, err_pattern

    def set_page_limit(self, lines=100): # 0 is no limite
        self.send_command("terminal pager lines %d" % lines)

    def set_page_no_limit(self):
        self.set_page_limit(0)

    def set_terminal_width(self, width=511):
        self.send_command("terminal width %d" % width)

    def exit(self):
        self.write_channel("exit")

    def write_memory(self):
        self.send_command("write memory")



class CiscoAsa(CiscoAsaConnection):

    def __init__(self, acl_name, params, conn_type):
        self.acl_name = acl_name
        super(CiscoAsaConnection, self).__init__(params, conn_type)

    def send_command(self, command, err_list=[], enter=True):
        #err_list += [r'ERROR: ']
        return super(CiscoAsa, self).send_command(command, err_list, enter)

    #############################################################################################
    # Info get command
    #############################################################################################

    def remark_info(self, remark):
        pattern =  r'^access-list (?P<id>\S+)( line (?P<line_num>[0-9]*))? remark - (?P<remark>\S+)$'
        reg = re.compile(pattern)
        match = reg.match(remark)
        if match == None:
            return None
        info = match.groupdict()
        for k, v in info.items():
            if v == None:
                del info[k]
        return info


    def get_ace_rule_info(self, ace):
        pattern =  r'^access-list (?P<id>\S+)( line (?P<line_num>[0-9]*))?( (?P<rule>[\S\s]+))'
        reg = re.compile(pattern)
        match = reg.match(ace)
        if match == None:
            return None
        info = match.groupdict()
        for k, v in info.items():
            if v == None:
                del info[k]
        return info

    def get_ace_detail_info(self, ace):
        pattern =  r'^access-list (?P<id>\S+)( line (?P<line_num>[0-9]*))? extended'
        pattern += r'( (?P<action>permit|deny) (?P<proto>ip|tcp|udp|icmp))'
        pattern += r'( (?P<user>user-group \S+|user \S+|object-group-user \S+))?'
        pattern += r'( (?P<src>host \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|any|any4|any6|object-group \S+|object \S+))' 
        pattern += r'( (?P<src_port>eq \d{1,5}|gt \d{1,5}|lt \d{1,5}|neq \d{1,5}|range \d{1,5} \d{1,5}|object-group \S+))?'
        pattern += r'( (?P<dst>host \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3} \d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|any|any4|any6|object-group \S+|object \S+))' 
        pattern += r'( (?P<dst_port>eq \d{1,5}|gt \d{1,5}|lt \d{1,5}|neq \d{1,5}|range \d{1,5} \d{1,5}|object-group \S+))?'
        pattern += r'( (?P<inactive>inactive))?'
        pattern += r'( (\(hitcnt=(?P<hitcnt>\S+)\) (\(inactive\))? 0x(?P<hash>[0-9a-z]*)))?'
        reg = re.compile(pattern)
        match = reg.match(ace)
        if match == None:
            return None
        info = match.groupdict()
        for k, v in info.items():
            if v == None:
                del info[k]
        # check validate
        if info['proto'] in ['ip', 'icmp'] and (info.has_key('src_port') or info.has_key('dst_port')):
            raise Exception('ERROR ACE: %s\nproto %s has port configuration!!!') % (ace, info['proto'])
            
        return info

    #############################################################################################
    # show command
    #############################################################################################

    def _show_with_more(self, cmd, stop_pattern=None):
        output, err_pattern = self.send_command(cmd, [r'<--- More --->$'])
        result = ""
        while 1:
            result += output
            if err_pattern == None:
                break
            elif stop_pattern and re.search(stop_pattern, result):
                output, err_pattern = self.send_command('q', enter=False)
                result += output
                break
            elif err_pattern == r'<--- More --->$':
                output, err_pattern = self.send_command(' ', [r'<--- More --->$'], enter=False)
        response_list = result.split("\r\n")[1:-1]
        for i in range(len(response_list)):
            if re.search(r"^<--- More --->\r              \r", response_list[i]):
                response_list[i] = response_list[i].replace("<--- More --->\r              \r", "")
            response_list[i] = response_list[i].replace('\r', '')
        return response_list

    def _show_acl_between(self, start_pattern, stop_pattern):
        if start_pattern == stop_pattern:
            raise Exception('Start pattern can not equal with Stop_pattern')
        cmd = "show access-list %s | begin %s" % (self.acl_name, start_pattern)
        response_list = self._show_with_more(cmd, stop_pattern)
        aces = []
        for ace in response_list:
            match_start = re.search(start_pattern, ace)
            match_stop = re.search(stop_pattern, ace)
            if not match_start and match_stop:
                aces.append(str(ace))
                break
            if re.search("^  ", ace):
                continue
            aces.append(str(ace))
        return aces

    def _show_run_acl_between(self, start_pattern, stop_pattern):
        if start_pattern == stop_pattern:
            raise Exception('Start pattern can not equal with Stop_pattern')
        cmd = "show run access-list %s | begin %s" % (self.acl_name, start_pattern)
        response_list = self._show_with_more(cmd, stop_pattern)
        aces = []
        for ace in response_list:
            match_start = re.search(start_pattern, ace)
            match_stop = re.search(stop_pattern, ace)
            if not match_start and match_stop:
                aces.append(str(ace))
                break
            aces.append(str(ace))
        return aces

    #############################################################################################
    # Basic op command
    #############################################################################################

    def ace_exist(self, filter):
        output = self.get_aces(self.acl_name, filter)
        '''
        if len(output) > 1:
            raise Exception("Ace contain %s has multi result: %s" % (filter, output))
        '''
        for o in output:
            if filter + "_" in o + "_":
                return True
        return False
        #return (False if len(output) == 0 else True)


    def remark_create_if_not_exist(self, remark, create_below):
        if not self.ace_exist(remark):
            ace = self.get_ace(create_below)
            info = self.remark_info(ace)
            self.add_remark(remark, int(info['line_num']) + 1)

    def get_aces(self, aclname, filter=None):
        if filter:
            cmd = u"show running-config access-list %s | inc %s" % (aclname, filter)
        else:
            cmd = u"show running-config access-list %s" % aclname
        text, err = self.send_command(cmd)
        if err:
            raise Exception("Get aces Error %s" % err)
        aces = text.replace('\r', '').split('\n')[1:-1]
        return aces

    def get_ace(self, filter):
        cmd = u"show access-list %s | inc %s" % (self.acl_name, filter)
        output, err_pattern = self.send_command(cmd)
        output = output.split('\r\n')[1:-1]
        if len(output) > 1:
            raise Exception("Ace contain `%s` has multi result: \n'  %s" % \
                    (filter, '\n  '.join(output)))
        if len(output) == 0:
            raise Exception("Ace contain `%s` does not exist!" % filter)
        return output[0]

    def get_remark(self, remark):
        return self.get_ace(" remark - %s" % remark)

    def get_remark_line(self, remark):
        ace = self.get_remark(remark)
        start_line = self.remark_info(ace).get('line_num', None)
        return start_line

    def add_remark(self, remark, line=0):
        ace = " remark - %s" % remark 
        if self.ace_exist(remark):
            raise Exception('add remark error: remark duplicate %s ' % ace)
        if line == 0:
    	    cmd = "access-list %s remark - %s" % (self.acl_name, remark)
        elif line > 0:
    	    cmd = "access-list %s line %d remark - %s" % (self.acl_name, line, remark)
        else:
            raise Exception("Line number is negative!")
        response_list = self._show_with_more(cmd)
        if len(response_list) > 0:
            raise Exception('add remark error:\nCMD:\n%s\nERROR:\n%s' % (cmd, '\n'.join(response_list)))

    def del_ace(self, rule, line=0):
        self.add_ace(rule, line, no=True)

    def add_ace(self, rule, line=0, no=False):
        if line == 0:
    	    cmd = "access-list %s %s" % (self.acl_name, rule)
            if no:
                cmd = "no " + cmd
        elif line > 0:
    	    cmd = "access-list %s line %d %s" % (self.acl_name, line, rule)
            if no:
                cmd = "no " + cmd
        else:
            raise Exception("Line number is negative!")

        response_list = self._show_with_more(cmd)
        if len(response_list) > 0:
            raise Exception('modify ace error:\nCMD:\n%s\nERROR:\n%s' % (cmd, '\n'.join(response_list)))

    def _exec_object_group_cmd(self, cmd):
        output = self._show_with_more(cmd)

        pattern = r"(does not exist|ERROR:)"
        if len(output) > 0 and re.search(pattern, '\n'.join(output)):
            raise Exception('Exec `%s` Error:\n%s' % (cmd, '\n'.join(output)))

    def object_group_exist(self, name):
        output = self._show_with_more("show object-group id %s" % name)
        if len(output) == 1 and re.search("does not exist$", output[0]):
            return False
        return True

    def create_object_group_user_if_not_exist(self, name):
        if not self.object_group_exist(name):
            self._exec_object_group_cmd("object-group user " + name)
            self._exec_object_group_cmd("user STUB\stubuser") # 新建时必须添加stub，否则该group 无法被引用

    def create_object_group_network_if_not_exist(self, name):
        if not self.object_group_exist(name):
            self._exec_object_group_cmd("object-group network " + name)
            self._exec_object_group_cmd("network-object host 1.1.1.1") # 新建时必须添加stub，否则该group 无法被引用

    #############################################################################################
    # object-group command
    #############################################################################################

    def get_object_group_contents(self, name):
        ret = []
        if not self.object_group_exist(name):
            raise Exception("Object group user `%s` dose not exist" % name)
        output = self._show_with_more("show running-config object-group id %s" % name)
        for line in output[1:]:
            ret.append(line.lstrip().rstrip())
        return ret

    def sync_object_group_user(self, name, users):
        self.create_object_group_user_if_not_exist(name)
        current_users = self.get_object_group_contents(name)
        current_users.remove('user STUB\stubuser') # 确保 stub 不会被删除
        add_users = list(set(users).difference(set(current_users)))
        del_users = list(set(current_users).difference(set(users)))
        self._exec_object_group_cmd("object-group user " + name)
        for cmd in add_users:
            self._exec_object_group_cmd(cmd)
        for cmd in del_users:
            self._exec_object_group_cmd('no ' + cmd)

    def del_object_group_user(self, name):
        self._exec_object_group_cmd("no object-group user " + name)

    def sync_object_group_network(self, name, networks):
        self.create_object_group_network_if_not_exist(name)
        current_networks = self.get_object_group_contents(name)
        current_networks.remove('network-object host 1.1.1.1') # 确保 stub 不会被删除
        add_networks = list(set(networks).difference(set(current_networks)))
        del_networks = list(set(current_networks).difference(set(networks)))
        self._exec_object_group_cmd("object-group network " + name)
        for cmd in add_networks:
            self._exec_object_group_cmd(cmd)
        for cmd in del_networks:
            self._exec_object_group_cmd('no ' + cmd)

    def del_object_group_network(self, name):
        self._exec_object_group_cmd("no object-group network " + name)

    #############################################################################################
    # Rule op command
    #############################################################################################


    def get_rules(self, rule_name):
        start_pattern = r"remark - %s" % rule_name
        stop_pattern = r"remark (?!- %s)" % rule_name
        rules = self._show_acl_between(start_pattern, stop_pattern)
        for i in range(len(rules)):
            rules[i] = rules[i].split('(hitcnt=')[0]
        return del_list_space(rules[:-1])

    def get_rules_content(self, rule_name):
        rules = self.get_rules(rule_name)
        if len(rules) < 1:
            raise Exception('Sync Rule Error: Rule %s do not exist' % rule_name)
        start_line = self.get_remark_line(rule_name)
        contents = []
        for r in rules:
            contents.append(self.get_ace_rule_info(r)['rule'])
        return int(start_line), contents

    def sync_rules(self, rule_name, new_rules):
        start_line, current_rules = self.get_rules_content(rule_name)
        # 生成操作表
        result, rsl = NBdiff(current_rules, new_rules)
        for r in reversed(result): # 先从屁股往上删除
            if r[0] == "-":
                self.del_ace(r[1])
        for r in result: # 再从脑袋往下添加
            if r[0] == "-":
                continue
            if r[0] == "+":
                if self.ace_exist(r[1]): 
                    msg = 'Sync Rules %s Error: \n`%s` found duplicate element'
                    raise Exception(msg)
                self.add_ace(r[1], start_line)
            start_line += 1
        # 检查添加是否正确
        start_line, current_rules = self.get_rules_content(rule_name)
        result, rsl = NBdiff(current_rules, new_rules) 
        for r in result:
            if r[0] != '=':
                raise Exception('Sync Rules %s not correct, diff current rules'\
                        ' & sync rules : \n  %s' % (rule_name, '\n  '.join(rsl)))

    def _sync_rules(self, rule_name, new_rules):
        current_rules = self.get_rules(rule_name)
        if len(current_rules) < 1:
            raise Exception('Sync Rule Error: Rule %s do not exist' % rule_name)
        result, rsl = NBdiff(cur_rule, new_rules)
        for r in reversed(result): # 先从屁股往上删除
            if r[0] == "-":
                info = self.get_ace_rule_info(r[1])
                self.del_ace(info['rule'], int(info['line_num']))
        for r in result:
            if r[0] == "+": # 再从头部往下添加
                info = self.get_ace_rule_info(r[1])
                if self.ace_exist(info['rule']):
                    msg = 'Sync Rules %s Error: \n`%s` found duplicate element'
                    raise Exception(msg)
                self.add_ace(info['rule'], int(info['line_num']))
        current_rules = self.get_rules(rule_name)
        result, rsl = NBdiff(current_rules, new_rules) 
        for r in result:
            if r[0] != '=':
                raise Exception('Sync Rules %s not correct, diff current rules'\
                        ' & sync rules : \n  %s' % (rule_name, '\n  '.join(rsl)))

    def del_rules(self, rule_name):
        current_rules = self.get_rules(rule_name)
        for r in reversed(current_rules): # 先从屁股往上删除
            info = self.get_ace_rule_info(r)
            self.del_ace(info['rule'], int(info['line_num']))
        current_rules = self.get_rules(rule_name)
        if len(current_rules) > 0:
            raise Exception('Group Rule Sync Del not correct, currnet: \n%s' % "\n".join(current_rules)) 


