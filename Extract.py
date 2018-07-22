# -*- coding: utf-8 -*-
import pefile, base64

class Format(object):
	def __init__(self, data):

		self.IP			= "[**] IP Address: " + data[0]
		self.Email		= "[**] Email: " + base64.b64decode(data[1])
		self.Password		= "[**] Password: " + base64.b64decode(data[2])
		self.SMTP		= "[**] SMTP Server: " + base64.b64decode(data[3])
		self.Unk		= "[**] Unknown Base64: " + base64.b64decode(data[4])
		self.Time_1		= data[5]
		self.URL		= "[**] Embedded URL: " + data[8]
		self.Persistence	= "[**] Persistence: " + data[10]
		self.Kill_Anti_Virus	= "[**] Kill Anti Virus: " + data[11]
		self.Download_And_Exec	= "[**] Download And Exec: " + data[12]
		self.Alter_NetComm	= data[13]
		self.Steal_Creds	= "[**] Steal Credentials (FileZilla, NoIP, IMVU): " +data[14]		# FileZilla, NoIP, IMVU
		self.Spread_USB		= "[**] Spread Logger VIA USB: " + data[15]
		self.Disable_TaskMgr	= "[**] Disable Task Manager: " + data[16]		
		self.Decrypt_Data_6	= data[17]
		self.StealSteam		= "[**] Steal Steam Data: " + data[18]
		self.DeleteCookies	= "[**] Delete IE and Firefox Cookies: " + data[19]
		self.Clip_ScreenShot	= "[**] Monitor Clipboard and Screenshot: " + data[20]		
		self.Modify_Hosts	= "[**] Modify Hosts File: " + data[21]
		self.DisableSR		= "[**] Disable System Restore: " + data[22]
		self.Disable_TaskMgr2	= data[23]
		self.Disable_Reg_CMD	= "[**] Disable Registry and CMD: " + data[24]
		self.ScreenShot		= "[**] Screenshot System: " + data[25]		
		self.Time_2		= data[26]
		self.Time_3		= data[27]
		self.Kill_OSK		= "[**] Kill On Screen Keyboard (OSK): " + data[28]
		self.DisableLUA_Consent	= data[29]
		self.Exfil_Method	= "[**] Exfiltration Method: " + data[30]
		self.NetCommValue	= "[**] Value stored in the NetComminucation Reg Key h2314: " + data[32]
		self.Blank		= data[33]

def Parse(overlay):

	overlay = overlay.split("<-_-_-|*-*ReVaLaTioN*-*|-_-_->")
	for index, item in enumerate(overlay):
		if len(item) <= 0:
			overlay[index] = "NULL"
		if item == '0':
			overlay[index] = "Gmail"
		elif item == '1':
			overlay[index] = "Live"
		elif item == '2':
			overlay[index] = "FTP Server"
		if item == "False":
			overlay[index] = "Deactivated"
		elif item == "True":
			overlay[index] = "Activated"
		
	Data = Format(overlay)
	Important_Data = [Data.IP, Data.Email, Data.Password, Data.SMTP, Data.Exfil_Method, Data.URL]
	Capabilities   = [Data.Persistence, Data.Kill_Anti_Virus, Data.Download_And_Exec, Data.Steal_Creds, Data.Spread_USB, Data.StealSteam,
			  Data.Modify_Hosts, Data.DeleteCookies, Data.Disable_Reg_CMD, Data.ScreenShot]
	for item in Important_Data:
		print item
	for item in Capabilities:
		print item
	
	

def main():

	print "Revalation Keylogger Config Extractor"
	filename = raw_input("Input the Keylogger's Filename: ")
	f = open(filename, "rb")			
	executable = f.read()
	pe = pefile.PE(filename)
	offset = pe.get_overlay_data_start_offset()
	overlay = executable[offset:]
	Parse(overlay)
	return 
	
if __name__ == "__main__":
	main()
