#!/usr/bin/env python3

import os, sys, uuid, argparse, textwrap, glob, json, base64, re
from datetime import datetime
from binascii import b2a_hex

hvt = ["512", "516", "519", "520"]

db = {}

# https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties
user_access_control = {
	"SCRIPT": 0x0001,
	"ACCOUNTDISABLE": 0x0002,
	"HOMEDIR_REQUIRED": 0x0008,
	"LOCKOUT": 0x0010,
	"PASSWD_NOTREQD": 0x0020,
	"PASSWD_CANT_CHANGE": 0x0040,
	"ENCRYPTED_TEXT_PWD_ALLOWED": 0x0080,
	"TEMP_DUPLICATE_ACCOUNT": 0x0100,
	"NORMAL_ACCOUNT": 0x0200,
	"INTERDOMAIN_TRUST_ACCOUNT": 0x0800,
	"WORKSTATION_TRUST_ACCOUNT": 0x1000,
	"SERVER_TRUST_ACCOUNT": 0x2000,
	"DONT_EXPIRE_PASSWORD": 0x10000,
	"MNS_LOGON_ACCOUNT": 0x20000,
	"SMARTCARD_REQUIRED": 0x40000,
	"TRUSTED_FOR_DELEGATION": 0x80000,
	"NOT_DELEGATED": 0x100000,
	"USE_DES_KEY_ONLY": 0x200000,
	"DONT_REQ_PREAUTH": 0x400000,
	"PASSWORD_EXPIRED": 0x800000,
	"TRUSTED_TO_AUTH_FOR_DELEGATION": 0x1000000,
	"PARTIAL_SECRETS_ACCOUNT": 0x04000000
}

# https://github.com/fox-it/BloodHound.py/blob/6b83660d3b5adedc24e5b2c2d142c524e320ad1c/bloodhound/ad/utils.py#L101
# I really didn't want to just copy paste this but this is the best way I can think of doing it so props to @dirkjanm
functional_level = {
	0: "2000 Mixed/Native",
	1: "2003 Interim",
	2: "2003",
	3: "2008",
	4: "2008 R2",
	5: "2012",
	6: "2012 R2",
	7: "2016"
}

# https://github.com/dirkjanm/ldapdomaindump/blob/ab1b4c38468509bb43b8943839e987c6680f1b5c/ldapdomaindump/__init__.py#L76
trust_flags = {
	"NON_TRANSITIVE":0x00000001,
	"UPLEVEL_ONLY":0x00000002,
	"QUARANTINED_DOMAIN":0x00000004,
	"FOREST_TRANSITIVE":0x00000008,
	"CROSS_ORGANIZATION":0x00000010,
	"WITHIN_FOREST":0x00000020,
	"TREAT_AS_EXTERNAL":0x00000040,
	"USES_RC4_ENCRYPTION":0x00000080,
	"CROSS_ORGANIZATION_NO_TGT_DELEGATION":0x00000200,
	"CROSS_ORGANIZATION_ENABLE_TGT_DELEGATION":0x00000800,
	"PIM_TRUST":0x00000400
}

def ret_os_path():
	if ((sys.platform == 'win32') and (os.environ.get('OS','') == 'Windows_NT')):
		return "\\"
	else:
		return "/"

def python_to_json(j):
	return j.replace("True", "true").replace("False", "false").replace("None", "null")

class User:

	def __init__(self):
		self.AllowedToDelegate = []
		self.ObjectIdentifier = ""
		self.PrimaryGroupSid = ""
		self.properties = {
			"name": None,
			"domain": None,
			"objectid": None,
			"distinguishedname": None,
			"highvalue": None,
			"unconstraineddelegation": None,
			"passwordnotreqd": None,
			"enabled": None,
			"lastlogon": None,
			"lastlogontimestamp": None,
			"pwdlastset": None,
			"dontreqpreauth": None,
			"pwdneverexpires": None,
			"sensitive": None,
			"serviceprincipalnames": [],
			"hasspn": None,
			"displayname": None,
			"email": None,
			"title": None,
			"homedirectory": None,
			"description": None,
			"userpassword": None,
			"admincount": None,
			"sidhistory": []
		}
		self.Aces = []
		self.SPNTargets = []
		self.HasSIDHistory = []

	def export(self):
		buf = '{' + '"AllowedToDelegate": {}, "ObjectIdentifier": "{}", "PrimaryGroupSid": "{}", "Properties": {}, "Aces": {}, "SPNTargets": {}, "HasSIDHistory": {}'.format(
			self.AllowedToDelegate,
			self.ObjectIdentifier,
			self.PrimaryGroupSid,
			json.dumps(self.properties, indent=4, separators=(",", ": "), sort_keys=False),
			self.Aces,
			self.SPNTargets,
			self.HasSIDHistory
			) + '}'
		return python_to_json(json.loads(json.dumps(buf, indent=4, sort_keys=False, separators=(",", ": "))))

class Computer:

	def __init__(self):
		self.ObjectIdentifier = ""
		self.AllowedToAct = []
		self.PrimaryGroupSid = ""
		self.LocalAdmins = []
		self.PSRemoteUsers = []
		self.properties = {
			"name": None,
			"objectid": None,
			"domain": None,
			"highvalue": None,
			"distinguishedname": None,
			"unconstraineddelegation": None,
			"enabled": None,
			"haslaps": None,
			"lastlogontimestamp": None,
			"pwdlastset": None,
			"serviceprincipalnames": [],
			"description": None,
			"operatingsystem": None
		}
		self.RemoteDesktopUsers = []
		self.DcomUsers = []
		self.AllowedToDelegate = []
		self.Sessions = []
		self.Aces = []

	def export(self):
		buf = '{' + '"ObjectIdentifier": "{}", "AllowedToAct": {}, "PrimaryGroupSid": "{}", "LocalAdmins": {}, "PSRemoteUsers": {}, "Properties": {}, "RemoteDesktopUsers": {}, "DcomUsers": {}, "AllowedToDelegate": {}, "Sessions": {}, "Aces": {}'.format(
			self.ObjectIdentifier,
			self.AllowedToAct,
			self.PrimaryGroupSid,
			json.dumps(self.LocalAdmins),
			self.PSRemoteUsers,
			json.dumps(self.properties),
			self.RemoteDesktopUsers,
			self.DcomUsers,
			self.RemoteDesktopUsers,
			self.AllowedToDelegate,
			self.Sessions,
			self.Aces,
			) + '}'
		return python_to_json(json.loads(json.dumps(buf, indent=4, sort_keys=False, separators=(",", ": "))))

class Group:

	def __init__(self):
		self.ObjectIdentifier = None
		self.properties = {
			"domain": None,
			"objectid": None,
			"highvalue": None,
			"name": None,
			"distinguishedname": None,
			"admincount": None,
			"description": None
		}
		self.Members = []
		self.Aces = []

	def export(self):
		#self.sanitize()
		buf = '{' + '"ObjectIdentifier": "{}", "Properties": {}, "Members": {}, "Aces": {}'.format(
			self.ObjectIdentifier,
			json.dumps(self.properties),
			json.dumps(self.Members),
			self.Aces
			) + '}'
		return python_to_json(json.loads(json.dumps(buf, indent=4, sort_keys=False, separators=(",", ": "))))

class Domain:

	def __init__(self):
		self.ObjectIdentifier = None
		self.properties = {
			"name": None,
			"domain": None,
			"highvalue": True,
			"objectid": None,
			"distinguishedname": None,
			"description": None,
			"functionallevel": None
		}
		self.Trusts = []
		self.Aces = []
		self.Links = []
		self.Users = []
		self.Computers = []
		self.ChildOus = []

	def export(self):
		buf = '{' + '"ObjectIdentifier": "{}", "Properties": {}, "Trusts": {}, "Aces": {}, "Links": {}, "Users": {}, "Computers": {}, "ChildOus": {}'.format(
			self.ObjectIdentifier,
			json.dumps(self.properties),
			json.dumps(self.Trusts),
			self.Aces,
			self.Links,
			self.Users,
			self.Computers,
			self.ChildOus
			) + '}'
		return python_to_json(json.loads(json.dumps(buf, indent=4, sort_keys=False, separators=(",", ": "))))

def check(attr, mask):
	if ((attr & mask) > 0):
		return True
	return False

def to_epoch(longform):
	# 2021-09-30 05:28:09.685524+00:00
	try:
		utc_time = datetime.strptime(longform, "%Y-%m-%d %H:%M:%S.%f+00:00")
		epoch_time = int((utc_time - datetime(1970, 1, 1)).total_seconds())
		return int(epoch_time)
	except ValueError:
		return -1

def parse_users(input_folder, output_folder, bh_version):
	# https://github.com/dzhibas/SublimePrettyJson/blob/af5a6708d308f60787499e360081bf92afe66156/PrettyJson.py#L48
	brace_newline = re.compile(r'^((\s*)".*?":)\s*([{])', re.MULTILINE)
	bracket_newline = re.compile(r'^((\s*)".*?":)\s*([\[])', re.MULTILINE)
	count = 0
	j = json.loads(open(input_folder + ret_os_path() + "domain_users.json", "r").read())
	buf = '{"users": ['
	for user in j:
		u = User()
		u.ObjectIdentifier = user['attributes']['objectSid'][0]
		u.PrimaryGroupSid = '-'.join(user['attributes']['objectSid'][0].split("-")[:-1]) + "-" + str(user['attributes']['primaryGroupID'][0])

		if (('userPrincipalName' in user['attributes'].keys()) and ("/" not in str(user['attributes']['userPrincipalName'][0]))):
			u.properties['name'] = str(user['attributes']['userPrincipalName'][0]).upper()
		else:
			u.properties['name'] = str(user['attributes']['sAMAccountName'][0]).upper() + "@" + '.'.join(str(user['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper()

		if 'userPrincipalName' in user['attributes'].keys():
			if "@" in str(user['attributes']['userPrincipalName'][0]):
				u.properties['domain'] = str(user['attributes']['userPrincipalName'][0]).upper().split("@")[1]
			else:
				u.properties['domain'] = str(user['attributes']['userPrincipalName'][0]).upper()
		else:
			u.properties['domain'] = str(u.properties["name"]).upper().split("@")[1]

		u.properties['objectid'] = user['attributes']['objectSid'][0]
		u.properties['distinguishedname'] = user['attributes']['distinguishedName'][0]

		if ("$" in u.properties['distinguishedname']):
			db[u.properties['distinguishedname']] = [u.ObjectIdentifier, "Computer"]
		else:
			db[u.properties['distinguishedname']] = [u.ObjectIdentifier, "User"]

		u.properties['highvalue'] = False
		for h in hvt:
			if (h in str(user['attributes']['primaryGroupID'][0])):
				u.properties['highvalue'] = True


		u.properties['unconstraineddelegation'] = False
		if check(user['attributes']['userAccountControl'][0], user_access_control['TRUSTED_FOR_DELEGATION']):
			u.properties['unconstraineddelegation'] = True

		# PASSWD_NOTREQD = 0x0020
		u.properties["passwordnotreqd"] = False
		if check(user['attributes']['userAccountControl'][0], user_access_control['PASSWD_NOTREQD']):
			u.properties["passwordnotreqd"] = True

		# ACCOUNTDISABLE = 0x0002
		u.properties["enabled"] = False
		if (not check(user['attributes']['userAccountControl'][0], user_access_control['ACCOUNTDISABLE'])):
			u.properties['enabled'] = True

		if 'lastLogon' in user['attributes'].keys():
			u.properties['lastlogon'] = to_epoch(user['attributes']['lastLogon'][0])
		else:
			u.properties['lastlogon'] = -1

		if 'lastLogonTimestamp' in user['attributes'].keys():
			u.properties['lastlogontimestamp'] = to_epoch(user['attributes']['lastLogonTimestamp'][0])
		else:
			u.properties['lastlogontimestamp'] = -1

		if 'pwdLastSet' in user['attributes'].keys():
			u.properties['pwdlastset'] = to_epoch(user['attributes']['pwdLastSet'][0])
		else:
			u.properties['pwdlastset'] = -1

		u.properties['dontreqpreauth'] = False
		if check(user['attributes']['userAccountControl'][0], user_access_control['DONT_REQ_PREAUTH']):
			u.properties["dontreqpreauth"] = True

		u.properties['pwdneverexpires'] = False
		if check(user['attributes']['userAccountControl'][0], user_access_control['DONT_EXPIRE_PASSWORD']):
			u.properties["pwdneverexpires"] = True

		u.properties['sensitive'] = False
		u.properties['serviceprincipalnames'] = []

		if 'servicePrincipalName' in user['attributes'].keys():
			u.properties['hasspn'] = True
			for spn in user['attributes']['servicePrincipalName']:
				u.properties['serviceprincipalnames'].append(spn)
		else:
			u.properties['hasspn'] = False


		if 'displayName' in user['attributes'].keys():
			u.properties['displayname'] = user['attributes']['displayName'][0]
		else:
			u.properties['displayname'] = user['attributes']['sAMAccountName'][0]

		u.properties['email'] = None
		u.properties['title'] = None
		u.properties['homedirectory'] = None

		if 'description' in user['attributes'].keys():
			u.properties['description'] = user['attributes']['description'][0]
		else:
			u.properties['description'] = None

		u.properties['userpassword'] = None

		if 'adminCount' in user['attributes'].keys():
			u.properties['admincount'] = True
		else:
			u.properties['admincount'] = False

		u.properties['sidhistory'] = []

		u.Aces = []
		u.SPNTargets = []
		u.HasSIDHistory = []

		buf += u.export() + ', '
		count += 1

	with open(output_folder + ret_os_path() + "users.json", "w") as outfile:
		buf = bracket_newline.sub(r"\1\n\2\3", bracket_newline.sub(r"\1\n\2\3", json.dumps(json.loads(buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "users", "count": {}, "version": {}'.format(count, bh_version) + '}}'), indent=4, sort_keys=False, separators=(",", ": "))))
		outfile.write(buf)
	buf = ""

def build_la_dict(domain_sid, group_sid, member_type):
	return { "MemberId" : domain_sid + '-' + group_sid, "MemberType": member_type }

def parse_computers(input_folder, output_folder, bh_version):
	# https://github.com/dzhibas/SublimePrettyJson/blob/af5a6708d308f60787499e360081bf92afe66156/PrettyJson.py#L48
	brace_newline = re.compile(r'^((\s*)".*?":)\s*([{])', re.MULTILINE)
	bracket_newline = re.compile(r'^((\s*)".*?":)\s*([\[])', re.MULTILINE)
	count = 0
	j = json.loads(open(input_folder + ret_os_path() + "domain_computers.json", "r").read())
	buf = '{"computers": ['
	for comp in j:
		c = Computer()
		c.ObjectIdentifier = comp['attributes']['objectSid'][0]
		c.AllowedToAct = []
		c.PrimaryGroupSid = '-'.join(comp['attributes']['objectSid'][0].split("-")[:-1]) + "-" + str(comp['attributes']['primaryGroupID'][0])

		sid = '-'.join(comp['attributes']['objectSid'][0].split("-")[:-1])
		c.LocalAdmins = []
		c.LocalAdmins.append(build_la_dict(sid, "519", "Group"))
		c.LocalAdmins.append(build_la_dict(sid, "512", "Group"))
		c.LocalAdmins.append(build_la_dict(sid, "500", "User"))

		c.PSRemoteUsers = []

		if 'dNSHostName' in comp['attributes'].keys():
			c.properties["name"] = str(comp['attributes']['dNSHostName'][0]).upper()
		else:
			c.properties["name"] = str(comp['attributes']['distinguishedName'][0]).split(",CN=")[0].split("=")[1].replace(",OU", "") + "." + '.'.join(str(comp['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper()

		if 'userPrincipalName' in comp['attributes'].keys():
			c.properties["domain"] = str(comp['attributes']['userPrincipalName'][0]).upper().split(".")[1:]
		elif ("." in str(c.properties["name"])):
			c.properties["domain"] = '.'.join(str(c.properties["name"]).upper().split(".")[1:])
		else:
			# need to manually build domain based off object
			c.properties["domain"] = '.'.join(str(comp['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper()

		c.properties["objectid"] = comp['attributes']['objectSid'][0]

		c.properties["distinguishedname"] = comp['attributes']['distinguishedName'][0]

		c.properties["highvalue"] = False
		for h in hvt:
			if (h in str(comp['attributes']['primaryGroupID'][0])):
				c.properties["highvalue"] = True

		if 'userAccountControl' in comp['attributes'].keys():
			if check(comp['attributes']['userAccountControl'][0], user_access_control['TRUSTED_FOR_DELEGATION']):
				c.properties['unconstraineddelegation'] = True
		else:
			c.properties['unconstraineddelegation'] = False


		c.properties["enabled"] = False
		if (not check(comp['attributes']['userAccountControl'][0], user_access_control['ACCOUNTDISABLE'])):
			c.properties['enabled'] = True

		c.properties['haslaps'] = False # TDODO

		if 'lastLogonTimestamp' in comp['attributes'].keys():
			c.properties['lastlogontimestamp'] = to_epoch(comp['attributes']['lastLogonTimestamp'][0])
		else:
			c.properties['lastlogontimestamp'] = -1

		if 'pwdLastSet' in comp['attributes'].keys():
			c.properties['pwdlastset'] = to_epoch(comp['attributes']['pwdLastSet'][0])
		else:
			c.properties['pwdlastset'] = -1

		if 'servicePrincipalName' in comp['attributes'].keys():
			c.properties['serviceprincipalnames'] = comp['attributes']['servicePrincipalName']
		else:
			c.properties['serviceprincipalnames'] = None

		if 'description' in comp['attributes'].keys():
			c.properties['description'] = comp['attributes']['description'][0]
		else:
			c.properties['description'] = None

		if 'operatingSystem' in comp['attributes'].keys():
			c.properties['operatingsystem'] = comp['attributes']['operatingSystem']
		else:
			c.properties['operatingsystem'] = None

		buf += c.export() + ', '
		count += 1

	with open(output_folder + ret_os_path() + "computers.json", "w") as outfile:
		buf = bracket_newline.sub(r"\1\n\2\3", bracket_newline.sub(r"\1\n\2\3", json.dumps(json.loads(buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "computers", "count": {}, "version": {}'.format(count, bh_version) + '}}'), indent=4, sort_keys=False, separators=(",", ": "))))
		outfile.write(buf)
	buf = ""

def build_mem_dict(sid, member_type):
	return { "MemberId" : sid, "MemberType": member_type }

def parse_groups(input_folder, output_folder, no_users, bh_version):
	# https://github.com/dzhibas/SublimePrettyJson/blob/af5a6708d308f60787499e360081bf92afe66156/PrettyJson.py#L48
	brace_newline = re.compile(r'^((\s*)".*?":)\s*([{])', re.MULTILINE)
	bracket_newline = re.compile(r'^((\s*)".*?":)\s*([\[])', re.MULTILINE)
	count = 0

	if (no_users):
		j = json.loads(open(input_folder + ret_os_path() + "domain_users.json", "r").read())
		for user in j:
			u = user['attributes']['distinguishedName'][0]
			if ("$" in u):
				db[u] = [user['attributes']['objectSid'][0], "Computer"]
			else:
				db[u] = [user['attributes']['objectSid'][0], "User"]

	j = json.loads(open(input_folder + ret_os_path() + "domain_groups.json", "r").read())

	# fist build up group sids
	for group in j:
		db[group['attributes']['distinguishedName'][0]] = [group['attributes']['objectSid'][0], "Group"]

	buf = '{"groups": ['
	# now build up the whole file
	for group in j:
		g = Group()
		g.ObjectIdentifier = group['attributes']['objectSid'][0]

		if 'userPrincipalName' in group['attributes'].keys():
			g.properties['name'] = str(group['attributes']['userPrincipalName'][0]).upper()
		else:
			g.properties['name'] = str(group['attributes']['distinguishedName'][0]).split(",CN=")[0].split("=")[1].replace(",OU", "").upper() + "@" + '.'.join(str(group['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper()

		if 'userPrincipalName' in group['attributes'].keys():
			g.properties['domain'] = str(group['attributes']['userPrincipalName'][0]).upper().split("@")[1]
		else:
			g.properties['domain'] = str(g.properties["name"]).upper().split("@")[1]

		g.properties['objectid'] = group['attributes']['objectSid'][0]

		g.properties['highvalue'] = False
		for h in hvt:
			if (h in str(group['attributes']['objectSid'][0]).split("-")[-1:]):
				g.properties['highvalue'] = True

		g.properties['distinguishedname'] = group['attributes']['distinguishedName'][0]

		if 'adminCount' in group['attributes'].keys():
			g.properties['admincount'] = True
		else:
			g.properties['admincount'] = False

		if 'description' in group['attributes'].keys():
			g.properties['description'] = group['attributes']['description'][0]
		else:
			g.properties['description'] = None

		try:
			for m in group['attributes']['member']:
				t = db[m]
				g.Members.append(build_mem_dict(t[0], t[1]))
		except:
			pass

		buf += g.export() + ', '
		count += 1

	with open(output_folder + ret_os_path() + "groups.json", "w") as outfile:
		buf = bracket_newline.sub(r"\1\n\2\3", bracket_newline.sub(r"\1\n\2\3", json.dumps(json.loads(buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "groups", "count": {}, "version": {}'.format(count, bh_version) + '}}'), indent=4, sort_keys=False, separators=(",", ": "))))
		outfile.write(buf)
	buf = ""

# https://stackoverflow.com/questions/33188413/python-code-to-convert-from-objectsid-to-sid-representation
def sid_to_str(sid):
	try:
		# Python 3
		if str is not bytes:
			# revision
			revision = int(sid[0])
			# count of sub authorities
			sub_authorities = int(sid[1])
			# big endian
			identifier_authority = int.from_bytes(sid[2:8], byteorder='big')
			# If true then it is represented in hex
			if identifier_authority >= 2 ** 32:
				identifier_authority = hex(identifier_authority)

			# loop over the count of small endians
			sub_authority = '-' + '-'.join([str(int.from_bytes(sid[8 + (i * 4): 12 + (i * 4)], byteorder='little')) for i in range(sub_authorities)])
		# Python 2
		else:
			revision = int(b2a_hex(sid[0]))
			sub_authorities = int(b2a_hex(sid[1]))
			identifier_authority = int(b2a_hex(sid[2:8]), 16)
			if identifier_authority >= 2 ** 32:
				identifier_authority = hex(identifier_authority)

			sub_authority = '-' + '-'.join([str(int(b2a_hex(sid[11 + (i * 4): 7 + (i * 4): -1]), 16)) for i in range(sub_authorities)])
		objectSid = 'S-' + str(revision) + '-' + str(identifier_authority) + sub_authority

		return objectSid
	except Exception:
		pass

def parse_domains(input_folder, output_folder, bh_version):
	# https://github.com/dzhibas/SublimePrettyJson/blob/af5a6708d308f60787499e360081bf92afe66156/PrettyJson.py#L48
	brace_newline = re.compile(r'^((\s*)".*?":)\s*([{])', re.MULTILINE)
	bracket_newline = re.compile(r'^((\s*)".*?":)\s*([\[])', re.MULTILINE)

	count = 0
	sid = None
	j = json.loads(open(input_folder + ret_os_path() + "domain_policy.json", "r").read())
	buf = '{"domains": ['
	for dom in j:
		d = Domain()
		if 'objectSid' in dom['attributes'].keys():
			d.ObjectIdentifier = dom['attributes']['objectSid'][0]
			d.properties['objectid'] = dom['attributes']['objectSid'][0]
		else:
			d.ObjectIdentifier = None
			d.properties['objectid'] = None

#		if 'name' in dom['attributes'].keys():
#			d.properties['name'] = dom['attributes']['name'][0].upper()
#		else:
#			d.properties['name'] = None

		if 'cn' in dom['attributes'].keys():
			d.properties['domain'] = dom['attributes']['cn'][0].upper()
		elif 'distinguishedName' in dom['attributes'].keys():
			d.properties['domain'] = dom['attributes']['distinguishedName'][0].upper().replace(",DC=", ".").replace("DC=", "")
		else:
			d.properties['domain'] = dom['attributes']['cn'][0].upper()

		d.properties['name'] = d.properties['domain']

		if 'distinguishedName' in dom['attributes'].keys():
			d.properties['distinguishedname'] = dom['attributes']['distinguishedName'][0].upper()
		elif 'dn' in dom.keys():
			d.properties['distinguishedname'] = dom['dn'].upper()
		else:
			d.properties['distinguisedname'] = None

		if 'description' in dom['attributes'].keys():
			d.properties['description'] = dom['attributes']['description'][0]
		else:
			d.properties['description'] = None

		if 'msDS-Behavior-Version' in dom['attributes'].keys():
			d.properties['functionallevel'] = functional_level[int(dom['attributes']['msDS-Behavior-Version'][0])]
		else:
			d.properties['functionallevel'] = None
		buf += d.export() + ', '
		count += 1

	with open(output_folder + ret_os_path() + "domains.json", "w") as outfile:
		buf = bracket_newline.sub(r"\1\n\2\3", bracket_newline.sub(r"\1\n\2\3", json.dumps(json.loads(buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "domains", "count": {}, "version": {}'.format(count, bh_version) + '}}'), indent=4, sort_keys=False, separators=(",", ": "))))
		outfile.write(buf)
	buf = ""


def parse_domain_trusts(input_folder, output_folder, bh_version):
	count = 0
	sid = None
	j = json.loads(open(input_folder + ret_os_path() + "domain_trusts.json", "r").read())
	buf = '{"domains": ['
	for dom in j:
		d = Domain()
		if ("base64".upper() in dom['attributes']['securityIdentifier'][0]['encoding'].upper()):
			sid = sid_to_str(base64.b64decode(dom['attributes']['securityIdentifier'][0]['encoded']))
			d.ObjectIdentifier = sid
		else:
			d.ObjectIdentifier = None
		d.properties['name'] = dom['attributes']['name'][0].upper()
		d.properties['domain'] = dom['attributes']['cn'][0].upper()
		d.properties['objectid'] = sid
		d.properties['distinguishedname'] = dom['attributes']['distinguishedName'][0].upper()

		if 'description' in dom['attributes'].keys():
			d.properties['description'] = dom['attributes']['description'][0]
		else:
			d.properties['description'] = None

		if 'msDS-Behavior-Version' in dom['attributes'].keys():
			d.properties['functionallevel'] = functional_level[int(dom['attributes']['msDS-Behavior-Version'][0])]
		else:
			d.properties['functionallevel'] = None

		target_domain_sid = None
		already_found = json.loads(open(output_folder + ret_os_path() + "domains.json", "r").read())
		for dom2 in already_found['domains']:
			if (dom['attributes']['trustPartner'][0].upper() == dom2['Properties']['domain']):
				target_domain_sid = dom2['ObjectIdentifier']

		sid_filtering = None
		if (dom['attributes']['trustAttributes'][0] & trust_flags['QUARANTINED_DOMAIN']):
			sid_filtering = True
		else:
			sid_filtering = False

		transitive = False
		if (dom['attributes']['trustAttributes'][0] & trust_flags['FOREST_TRANSITIVE']):
			transitive = True
			sid_filtering = True

		if (target_domain_sid):
			d.Trusts.append({
					"TargetDomain": dom['attributes']['trustPartner'][0].upper(),
					"TargetDomainSid": target_domain_sid,
					"IsTransitive": transitive, 
					"TrustDirection": int(dom['attributes']['trustDirection'][0]), 
					"TrustType": int(dom['attributes']['trustType'][0]), 
					"SidFilteringEnabled": sid_filtering
			})

		buf += d.export() + ', '
		count += 1

	j = json.loads(open(output_folder + ret_os_path() + "domains.json", "r").read())

	if (count > 0):
		new_domains = json.loads(buf[:-2] + "]}")
		for dom in new_domains['domains']:
			j['domains'].append(dom)
		j['meta']['count'] += count
		with open(output_folder + ret_os_path() + "domains.json", "w") as outfile:
			outfile.write(json.dumps(j))
	else:
		# we have no domain trusts, stop doing anything
		return

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
			formatter_class=argparse.RawDescriptionHelpFormatter,
			description='Convert ldapdomaindump to Bloodhound',
			epilog=textwrap.dedent('''Examples:\npython3 ldd2bh.py -i ldd -o bh''')
	)

	parser.add_argument('-i','--input', dest="input_folder", default=".", required=False, help='Input Directory for ldapdomaindump data, default: current directory')
	parser.add_argument('-o','--output', dest="output_folder", default=".", required=False, help='Output Directory for Bloodhound data, default: current directory')
	parser.add_argument('-a','--all', action='store_true', default=True, required=False, help='Output all files, default: True')
	parser.add_argument('-u','--users', action='store_true', default=False, required=False, help='Output only users, default: False')
	parser.add_argument('-c','--computers', action='store_true', default=False, required=False, help='Output only computers, default: False')
	parser.add_argument('-g','--groups', action='store_true', default=False, required=False, help='Output only groups, default: False')
	parser.add_argument('-d','--domains', action='store_true', default=False, required=False, help='Output only domains, default: False')
	parser.add_argument('-b','--bh-version', dest='bh_version', default=3, type=int, required=False, help='Bloodhound data format version (only 3 for now), default: 3')

	args = parser.parse_args()
	
	if ((args.bh_version != 3)):
		raise argparse.ArgumentTypeError('Invalid Bloodhound file version given! New version support might come in the future.')

	if ((args.input_folder != ".") and (args.output_folder != ".")):
		if (sum([args.users, args.computers, args.groups, args.domains]) == 0):
			args.users = True
			args.computers = True
			args.groups = True
			args.domains = True
		if (args.users):
			print("Parsing users...")
			parse_users(args.input_folder, args.output_folder, args.bh_version)
		if (args.computers):
			print("Parsing computers...")
			parse_computers(args.input_folder, args.output_folder, args.bh_version)
		if (args.groups):
			print("Parsing groups...")
			parse_groups(args.input_folder, args.output_folder, not args.users, args.bh_version)
		if (args.domains):
			print("Parsing domains...")
			parse_domains(args.input_folder, args.output_folder, args.bh_version)
			parse_domain_trusts(args.input_folder, args.output_folder, args.bh_version)
		print("Done!")
	else:
		parser.print_help()
