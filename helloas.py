#! /usr/bin/env python
#coding=utf-8
# Description: helloas.py is a command line tool for uploading,
# retrieving and managing data in OAS Archived Storage.
#===========================================================
# Author: colynn.liu
# Email:colynnliu@foxmail.com
# License: GPL Version 2

import sys
reload(sys)
sys.setdefaultencoding('utf-8')
if float("%d.%d" % (sys.version_info[0], sys.version_info[1])) < 2.4:
    sys.stderr.write("ERROR: Python 2.4 or higher required, sorry.\n")
    sys.exit(1)

from os import devnull,remove
from os.path import basename,isfile,exists,basename
import subprocess
import time
import socket

import ConfigParser
import json
from base64 import b64encode,b64decode

from oas.oas_api import OASAPI
from oas.ease.vault import Vault
from oas.ease.exceptions import OASServerError

#from oas.ease.uploader import Uploader


CONFIGFILE="/etc/.oas.conf"
SECRET='}0;&KlQpLOZssxs(*%^3Kf{Q8*7Pp.+L.SgFDk,[~$co[q)Tb/_nMVSw2(D1b;o8asdsds'

def check_localfile(localfile):
    if not isfile(localfile):
        return False

def check_log_path(log_path):
    if not exists(log_path):
        return False  

def get_log_list(logconfig):
    '''
    return log_tar_file_list 
	# log_list= ['/opt/tomcat/2015_12_23_opt_tomcat_logs.tar.gz']
    '''
    log_list=[]
    days = logconfig['remain_days']
    for log_path in logconfig['log_path'].split(','):
        # delete the right spaces
        log_path = log_path.rstrip()
        
        # base on log_path defined tar file name
        log_name = log_path.split('/')
        tar_name = "_".join(log_name)
        if len(tar_name) >= 120:
            tar_name = tar_name[0:120]
        date_time = time.strftime("%Y_%m_%d", time.localtime()) 
        tar_name = date_time + tar_name

        if check_log_path(log_path) == False:
            continue
        try:
            FNULL = open(devnull, 'w')
            subprocess.call("find " + log_path + " -mtime +" + days + " | xargs tar czvf " + log_path + "/" + tar_name + ".tar.gz",stdout=FNULL,stderr=subprocess.STDOUT, shell=True )
            log_file = log_path + "/" + tar_name  + ".tar.gz"
            if (check_localfile(log_file) != False):
                log_list.append(log_file)
                subprocess.call("find " + log_path + "/* -mtime +" + days + " | xargs rm -f ",stdout=FNULL,stderr=subprocess.STDOUT, shell=True )
        except subprocess.CalledProcessError,e:
            print e
            continue
    return log_list

class oas_config(object):
    def __init__(self,cnffile):
        self.oascnf = {}
        self.status = True
        try:
            config = self.read_config(cnffile)
            self.oascnf['access_key'] = str(self.decode(config.get("oas","access_key"),SECRET))
            self.oascnf['secret_key'] = str(self.decode(config.get("oas","secret_key"),SECRET))
            self.oascnf['vault_name'] = config.get("oas","vault_name")
            self.oascnf['server_host'] = config.get("oas","server_host")
            self.oascnf['log_path'] = config.get("default","log_path")
            self.oascnf['remain_days'] = config.get("default","remain_days")
        except Exception,e:
            print '*** Caught exception - Configuration File Error: %s :\n%s: %s\n' % (cnffile ,e.__class__, e)
            self.status = False

    def read_config(self,cnfconfig):
        '''
        read qiniu config file, return config instance
        '''
        config = ConfigParser.ConfigParser()
        config.readfp(open(cnfconfig))
        return config

    def encode(self,unicodeString,key):
        """
        for safe: encode password & store it into config filef
        """
        strorg = unicodeString.encode('utf-8')
        strlength = len(strorg)
        baselength = len(key)
        hh = []
        for i in range(strlength):
            hh.append(chr((ord(strorg[i])+ord(key[i % baselength]))%256))
        return b64encode(''.join(hh))

    def decode(self,orig,key):
        """
        for safe: read config file & decode password
        """
        strorg = b64decode(orig.encode('utf-8'))
        strlength=len(strorg)
        keylength=len(key)
        hh=[]
        for i in range(strlength):
            hh.append((ord(strorg[i])-ord(key[i%keylength]))%256)
        return ''.join(chr(i) for i in hh).decode('utf-8')

    def write_config(self):
        '''
        '''
        print "[INFO]: Start to config Aliyun OAS Service."
        access_key = raw_input("Please input your AccessKey: ")
        secret_key = raw_input("Please input your SecretKey: ")
        vaultName = socket.gethostname().strip()
        #region = raw_input("Please input your aliyun region: ")
        server_host="cn-hangzhou.oas.aliyuncs.com"
       
        try:
            Access = self.encode(access_key,SECRET)
            Secret = self.encode(secret_key,SECRET)
        except Exception,e:
            print "[ERROR]: Failed to encrypt the Access_key/SecretKey\n %s" % e
            sys.exit(1)
        config = ConfigParser.RawConfigParser()
        config.add_section("oas")
        config.add_section("default")

        config.set("oas", 'access_key', Access)
        config.set("oas", 'secret_key', Secret)
        config.set("oas", 'server_host', server_host)
        config.set("oas", 'vault_name', vaultName)
        config.set("default", 'log_path', "/opt/tomcat/logs")
        config.set("default", 'remain_days', "90")
        cfgfile = open(CONFIGFILE, 'w+')
        config.write(cfgfile)
        print "Backup Configuration is saved into %s." % CONFIGFILE
        cfgfile.close()
    
class oasApi(object):
    def __init__(self,cnfconfig):
        self.cnfconfig = cnfconfig
        self.api = OASAPI(self.cnfconfig['server_host'],self.cnfconfig['access_key'], self.cnfconfig['secret_key'])
        self.vault_name = self.cnfconfig['vault_name']
        self.verify_vault()

    def verify_vault(self):
        '''
        check the vault name exist or not.
        '''
        try:
            self.vault = Vault.get_vault_by_name(self.api,self.vault_name) 
        except ValueError:
            self.vault = Vault.create_vault(self.api, self.vault_name)

    def upload(self, localfile):
        '''
        upload the file to vault, add the desc_info.
	    desc_info, vault_name + tar_name
        '''
        file_name = basename(localfile)
        desc_info = self.vault_name + file_name
        archive_id = self.vault.upload_archive(localfile, desc=desc_info)
        if archive_id != 0:
            FNULL = open(devnull, 'w')
            subprocess.call("rm -f " + localfile,stdout=FNULL,stderr=subprocess.STDOUT, shell=True )
            return 0

    def multi_upload(self, localfile):
        upload_id = self.vault.initiate_uploader(localfile)
        #create_multipart_upload(vault_id, partsize)
        uploader = self.vault.recover_uploader(upload_id)
        uploader.resume(localfile)

    def get_archive_id(self, key_name):
        '''
	base on key_name, retrieve the archived description.
	   if exists this item, return specific ArchiveId,
	   not exists the item, will return 0.
        #key_name = vault_name + tar_file_name
        '''
        inventory_tmp = ".retrieve_inventory.tmp"
        job = self.vault.retrieve_inventory()
        job.download_to_file(inventory_tmp)

        # check inventory tmp file, if not exist, return -1
        check_localfile(inventory_tmp)
        try:
            inventory_file = open(inventory_tmp,'r')
            inventory_json = json.load(inventory_file)
            key_name = self.vault_name + key_name
            for archive in inventory_json['ArchiveList']:
                if archive['ArchiveDescription'] == key_name:
                    return archive['ArchiveId'] 
            return 0
        finally:
            remove(inventory_tmp)

    def get_archive_list(self):
        '''
	show archived list include ArchiveFile and ArchiveId, when items more 20, will record it to a file.
	'''
	inventory_tmp = ".retrieve_inventory_list.tmp"
        job = self.vault.retrieve_inventory()
        job.download_to_file(inventory_tmp)

        # check inventory tmp file, if not exist, return -1
        check_localfile(inventory_tmp)
        try:
            inventory_file = open(inventory_tmp,'r')
            inventory_json = json.load(inventory_file)
	    if (len(inventory_json['ArchiveList']) >= 20):
	    	time_str = time.strftime("%Y_%m_%d_%M", time.localtime())
		archive_file = "/tmp/" + time_str + "_archive_list.txt"
		f1 = open(archive_file,'w')
		for archive in  inventory_json['ArchiveList']:
	 	    archive_line= "ArchiveFile: " + archive['ArchiveDescription'].split(self.vault_name)[1] + '\nArchiveId: ' + archive['ArchiveId'] + "\n"
		    f1.write(archive_line)
		    f1.write("\n")
		f1.close()
		print "Archive items more than 20, archived list records to the file."
		print "ArchiveList: " + archive_file
		sys.exit(0)
		      	
	    print "\nArchiveList:"
	    print "-"*120
            for archive in inventory_json['ArchiveList']:
	 	print "ArchiveFile: " + archive['ArchiveDescription'].split(self.vault_name)[1] + '\nArchiveId: ' + archive['ArchiveId'] + "\n"
        finally:
            remove(inventory_tmp)
            
    def download(self, key_name):
        '''
        download specific archived file.
        first setep, should create retrieve_archive job,
        then use the method of download_to_file get specific archived file.
        '''
        if not self.check_key_name(key_name):
            # get archive_id according to key_name
            archive_id = self.get_archive_id(key_name)
	    tar_name = key_name
        else:
            archive_id = key_name
	    date_time = time.strftime("%Y_%m_%d_%M", time.localtime())
	    tar_name = date_time + "_log_tmp.tar.gz"
	if archive_id == 0:
	    print key_name + " not exists."      
	    sys.exit(1)
        # 新建类型为archive-retrieval的Job任务
        job = self.vault.retrieve_archive(archive_id)
        
        # 下载Job任务输出到指定文件路径, 正常下载返回 None 值.
        status = job.download_to_file(tar_name)
        if status == None:
            print tar_name + " download succeed."

    def delete(self, key_name):
        '''
        delete specific archived file.
        return code:
            0 succeed; 
            1 not exists or deleted
        '''
	if not self.check_key_name(key_name):
            # get archive_id according to key_name
            archive_id = self.get_archive_id(key_name)
        else:
	    archive_id = key_name
        try:
            self.vault.delete_archive(archive_id)
            return 0
        except OASServerError,e:
            print e
            return 1
    def check_key_name(self,key_name):
 	'''
	'''
	key_len = len(key_name)
	find_status = key_name.find("_")
	if (key_len == 128) and (find_status == -1):
	    return True
	else:
	    return False
	

def main():
    from optparse import OptionParser
    parser = OptionParser()
    parser.add_option("-u", "--upload", dest="filename", help="upload a file to your vault ")
    parser.add_option("-d", "--download", dest="downloadfile", help='''download a archive file, -d [ArchiveId|ArchiveFile]
				use ArchiveId more fast,can get ArchiveId use "helloas.py -l"''')
    parser.add_option("-c", "--custom", action="store_true", dest="custom", help="upload custom files")
    parser.add_option("-l", "--list", action="store_true", dest="list", help="list ArchivedFiles and ArchivedIds")
    parser.add_option("", "--delete", dest="delete", help="from your vault delete a file ")
    (options, args) = parser.parse_args()

    cnf = oas_config(CONFIGFILE)
    if not cnf.status:
        print "ERROR: Can't load config file: %s" % CONFIGFILE
        cnf.write_config()
        sys.exit(0)

    cnfdict = cnf.oascnf
    qn = oasApi(cnfdict)

    if options.filename:
        qn.upload(options.filename)
        sys.exit(0)
    if options.downloadfile:
        qn.download(options.downloadfile)
        sys.exit(0)
    if options.delete:
        status = qn.delete(options.delete)
        print status
        sys.exit(0)

    if options.list:
	qn.get_archive_list()
	sys.exit(0)
    # base log_path and remain_days upload file
    if options.custom:
	log_list = get_log_list(cnfdict)
	for file in log_list:
	    qn.upload(file)

if __name__ == '__main__':
    main()
