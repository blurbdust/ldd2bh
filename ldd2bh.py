#!/usr/bin/env python3

import os, sys, uuid, argparse, textwrap, glob, json
from datetime import datetime

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
			self.properties,
			self.Aces,
			self.SPNTargets,
			self.HasSIDHistory
			) + '}'
		return buf.replace("'", '"').replace("`", "'").replace("True", "true").replace("False", "false").replace("None", "null")

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
			self.LocalAdmins,
			self.PSRemoteUsers,
			self.properties,
			self.RemoteDesktopUsers,
			self.DcomUsers,
			self.RemoteDesktopUsers,
			self.AllowedToDelegate,
			self.Sessions,
			self.Aces,
			) + '}'
		return buf.replace("'", '"').replace("True", "true").replace("False", "false").replace("None", "null")

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
			str(json.dumps(self.properties)),
			self.Members,
			self.Aces
			) + '}'
		return buf.replace("'", '"').replace("`", "'").replace("True", "true").replace("False", "false").replace("None", "null")

class Domain:

	def __init__(self):
		self.ObjectIdentifier = None
		self.Properties = {
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
			self.properties,
			self.Trusts,
			self.Aces,
			self.Links,
			self.Users,
			self.Computers,
			self.ChildOus
			) + '}'
		return buf.replace("'", '"').replace("`", "'").replace("True", "true").replace("False", "false").replace("None", "null")

def check(attr, mask):
	if ((attr & mask) > 0):
		return True
	return False

def to_epoch(longform):
	# 2021-09-30 05:28:09.685524+00:00
	utc_time = datetime.strptime(longform, "%Y-%m-%d %H:%M:%S.%f+00:00")
	epoch_time = int((utc_time - datetime(1970, 1, 1)).total_seconds())
	return int(epoch_time)

def parse_users(input_folder, output_folder):
	count = 0
	j = json.loads(open(input_folder + "/domain_users.json", "r").read())
	buf = '{"users": ['
	for user in j:
		u = User()
		u.ObjectIdentifier = user['attributes']['objectSid'][0]
		u.PrimaryGroupSid = '-'.join(user['attributes']['objectSid'][0].split("-")[:-1]) + "-" + str(user['attributes']['primaryGroupID'][0])

		try:
			u.properties['name'] = str(user['attributes']['userPrincipalName'][0]).upper()
		except:
			u.properties['name'] = str(user['attributes']['distinguishedName'][0]).split(",CN=")[0].split("=")[1] + "@" + '.'.join(str(user['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper()

		try:
			u.properties['domain'] = str(user['attributes']['userPrincipalName'][0]).upper().split("@")[1]
		except:
			u.properties['domain'] = str(u.properties["name"]).upper().split("@")[1]

		u.properties['objectid'] = user['attributes']['objectSid'][0]
		u.properties['distinguishedname'] = user['attributes']['distinguishedName'][0].replace('"', '`').replace("'", "`")

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

		try:
			u.properties['lastlogon'] = to_epoch(user['attributes']['lastLogon'][0])
		except:
			u.properties['lastlogon'] = -1

		try:
			u.properties['lastlogontimestamp'] = to_epoch(user['attributes']['lastLogonTimestamp'][0])
		except:
			u.properties['lastlogontimestamp'] = -1
		try:
			u.properties['pwdlastset'] = to_epoch(user['attributes']['pwdLastSet'][0])
		except:
			u.properties['pwdlastset'] = -1

		u.properties['dontreqpreauth'] = False
		if check(user['attributes']['userAccountControl'][0], user_access_control['DONT_REQ_PREAUTH']):
			u.properties["dontreqpreauth"] = True

		u.properties['pwdneverexpires'] = False
		if check(user['attributes']['userAccountControl'][0], user_access_control['DONT_EXPIRE_PASSWORD']):
			u.properties["pwdneverexpires"] = True

		u.properties['sensitive'] = False
		u.properties['serviceprincipalnames'] = []
		try:
			u.properties['hasspn'] = user['attributes']['servicePrincipalName'][0]
		except:
			u.properties['hasspn'] = False

		try:
			u.properties['displayname'] = user['attributes']['displayName'][0].replace('"', '`').replace("'", "`")
		except:
			u.properties['displayname'] = user['attributes']['sAMAccountName'][0].replace('"', '`').replace("'", "`")
		u.properties['email'] = None
		u.properties['title'] = None
		u.properties['homedirectory'] = None
		try:
			u.properties['description'] = user['attributes']['description'][0].replace('"', '`').replace("'", "`")
		except:
			u.properties['description'] = None
		u.properties['userpassword'] = None
		u.properties['admincount'] = None # TODO
		u.properties['sidhistory'] = []

		u.Aces = []
		u.SPNTargets = []
		u.HasSIDHistory = []

		buf += u.export() + ', '
		count += 1

	buf = buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "users", "count": {}, "version": 3'.format(count) + '}}'

	with open(output_folder + "/users.json", "w") as outfile:
		outfile.write(buf)
	buf = ""

def build_la_dict(domain_sid, group_sid, member_type):
	return { "MemberId" : domain_sid + '-' + group_sid, "MemberType": member_type }

def parse_computers(input_folder, output_folder):
	count = 0
	j = json.loads(open(input_folder + "/domain_computers.json", "r").read())
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

		try:
			c.properties["name"] = str(comp['attributes']['userPrincipalName'][0]).upper()
		except:
			c.properties["name"] = str(comp['attributes']['distinguishedName'][0]).split(",CN=")[0].split("=")[1].replace(",OU", "") + "." + '.'.join(str(comp['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper()

		try:
			c.properties["domain"] = str(comp['attributes']['userPrincipalName'][0]).upper().split(".")[1]
		except:
			c.properties["domain"] = str(c.properties["name"]).upper().split(".")[1]

		c.properties["objectid"] = comp['attributes']['objectSid'][0]

		c.properties["distinguishedname"] = comp['attributes']['distinguishedName'][0].replace('"', '`').replace("'", "`")

		c.properties["highvalue"] = False
		for h in hvt:
			if (h in str(comp['attributes']['primaryGroupID'][0])):
				c.properties["highvalue"] = True

		c.properties['unconstraineddelegation'] = False
		try:
			if check(comp['attributes']['userAccountControl'][0], user_access_control['TRUSTED_FOR_DELEGATION']):
				c.properties['unconstraineddelegation'] = True
		except:
			# pass because we already set as false
			pass

		c.properties["enabled"] = False
		if (not check(comp['attributes']['userAccountControl'][0], user_access_control['ACCOUNTDISABLE'])):
			c.properties['enabled'] = True

		c.properties['haslaps'] = False # TDODO

		try:
			c.properties['lastlogontimestamp'] = to_epoch(comp['attributes']['lastLogonTimestamp'][0])
		except:
			c.properties['lastlogontimestamp'] = -1
		try:
			c.properties['pwdlastset'] = to_epoch(comp['attributes']['pwdLastSet'][0])
		except:
			c.properties['pwdlastset'] = -1
		try:
			c.properties['serviceprincipalnames'] = comp['attributes']['servicePrincipalName']
		except:
			c.properties['serviceprincipalnames'] = None

		try:
			c.properties['description'] = comp['attributes']['description'][0].replace('"', '`').replace("'", "`")
		except:
			c.properties['description'] = None

		try:
			c.properties['operatingsystem'] = comp['attributes']['operatingSystem']
		except:
			c.properties['operatingsystem'] = None



		buf += c.export() + ', '
		count += 1

	buf = buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "computers", "count": {}, "version": 3'.format(count) + '}}'

	with open(output_folder + "/computers.json", "w") as outfile:
		outfile.write(buf)
	buf = ""

def build_mem_dict(sid, member_type):
	return { "MemberId" : sid, "MemberType": member_type }

def parse_groups(input_folder, output_folder):
	count = 0
	j = json.loads(open(input_folder + "/domain_groups.json", "r").read())

	# fist build up group sids
	for group in j:
		db[group['attributes']['distinguishedName'][0]] = [group['attributes']['objectSid'][0], "Group"]
		#print(db[group['attributes']['distinguishedName'][0]])

	buf = '{"groups": ['
	# now build up the whole file
	f = open(output_folder + "/groups.json", "w")
	for group in j:
		g = Group()
		g.ObjectIdentifier = group['attributes']['objectSid'][0]

		try:
			g.properties['name'] = str(group['attributes']['userPrincipalName'][0]).upper().replace('"', '`').replace("'", "`")
		except:
			g.properties['name'] = str(group['attributes']['distinguishedName'][0]).split(",CN=")[0].split("=")[1].replace(",OU", "").replace('"', '`').replace("'", "`") + "@" + '.'.join(str(group['attributes']['distinguishedName'][0]).split(",DC=")[1:]).upper().replace('"', '`').replace("'", "`")

		try:
			g.properties['domain'] = str(group['attributes']['userPrincipalName'][0]).upper().split("@")[1]
		except:
			g.properties['domain'] = str(g.properties["name"]).upper().split("@")[1].replace('"', '`').replace("'", "`")

		g.properties['objectid'] = group['attributes']['objectSid'][0]

		g.properties['highvalue'] = False
		for h in hvt:
			if (h in str(group['attributes']['objectSid'][0]).split("-")[-1:]):
				g.properties['highvalue'] = True

		g.properties['distinguishedname'] = group['attributes']['distinguishedName'][0].replace('"', '`').replace("'", "`")

		g.properties['admincount'] = False # TODO

		try:
			g.properties['description'] = group['attributes']['description'][0].replace('"', '`').replace("'", "`")
		except:
			g.properties['description'] = None

		try:
			for m in group['attributes']['member']:
				t = db[m]
				g.Members.append(build_mem_dict(t[0], t[1]))
		except:
			pass

		count += 1
		if (count < len(j)):
			buf += g.export() + ', '
		else:
			buf += g.export()
		f.write(buf)
		buf = ""

	buf = '],' + ' "meta": ' + '{' + '"type": "groups", "count": {}, "version": 3'.format(count) + '}}'
	f.write(buf)
	f.close()
	#with open(output_folder + "/groups.json", "w") as outfile:
	#	outfile.write(buf)

def parse_domains(input_folder, output_folder):
	count = 0
	j = json.loads(open(input_folder + "/domain_trusts.json", "r").read())
	buf = '{"domains": ['
	for dom in j:
		d = Domain()
		d.ObjectIdentifier = dom['attributes']['objectSid'][0]



		buf += d.export() + ', '
		count += 1

	buf = buf[:-2] + '],' + ' "meta": ' + '{' + '"type": "domains", "count": {}, "version": 3'.format(count) + '}}'

	with open(output_folder + "/domains.json", "w") as outfile:
		outfile.write(buf)



def init(input_folder, output_folder):
	print("Parsing users...")
	parse_users(input_folder, output_folder)
	print("Parsing computers...")
	parse_computers(input_folder, output_folder)
	print("Parsing groups...")
	parse_groups(input_folder, output_folder)
	print("Done!")
	#parse_domains(input_folder, output_folder)




if __name__ == '__main__':
	parser = argparse.ArgumentParser(
			formatter_class=argparse.RawDescriptionHelpFormatter,
			description='Convert ldapdomaindump to Bloodhound',
			epilog=textwrap.dedent('''Examples:\npython3 ldd2bh.py -i ldd -o bh''')
	)

	parser.add_argument('-i','--input', dest="input_folder", default=".", required=False, help='Input Directory for ldapdomaindump data, default: current directory')
	parser.add_argument('-o','--output', dest="output_folder", default=".", required=False, help='Output Directory for Bloodhound data, default: current directory')
	#parser.add_argument('-u','--users', dest="", default=".", required=False, help='Output Directory for Bloodhound data, default: current directory')
	#parser.add_argument('-c','--computers', '--comps' dest="output_folder", default=".", required=False, help='Output Directory for Bloodhound data, default: current directory')
	#parser.add_argument('-g','--groups', dest="output_folder", default=".", required=False, help='Output Directory for Bloodhound data, default: current directory')

	args = parser.parse_args()

	if ((args.input_folder != ".") and (args.output_folder != ".")):
		#do things
		init(args.input_folder, args.output_folder)
	else:
		parser.print_help()
