taskHijacker
======================

# Description
This script has the purpose to facilitate practical Proof-of-Concept when testing Task Hijacking vulnerability on Android apps. 
It permits to turn an harmless APK into a malicious APK able to exploit the following specific Task Hijacking security issues:

(1) when the victim APK is configured with an activity having the flag "launchMode" set 
    to "singleTask", or the APK presents an activity that is started using Intent configured
    with the flag "FLAG_ACTIVITY_NEW_TASK"                                            

(2) when the victim APK is configured with an activity having the flag "allowTaskReparenting" 
    set to "true"                                                             

(3) when the malicious APK is configured with an activity having both the flag "allowTaskReparenting" 
    set to "true" and the flag "taskAffinity" set to the victim package value (NOTE: this issue 
    is related to an unsafe feature of Android OS, then works against any victim APK).  


Optionally, the script allows to set a custom background image on the attacker APK in 
order to mask it (e.g. using the home screen of the victim APK) on device's screen during the 
Task Hijacking PoC attack.


# Requirements:
In order to patch the attacker APK it is needed to use a keystore to re-sign it.
In addition the following tools are necessary:
* apktool
* zipalign
* apksigner


# References
* https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf



# Usage
In order to run the taskHijacker script it is needed at least to specify an exploitation mode ('--misconfig_task'/'-m' or '--cuckoo_task'/'-c'), 
the victim app package-name, and the path where is located your harmless APK to turn into a malicious APK.
In particular, regarding the exploitation modes:
* 'misconfig_task' allows to exploit the Task Hijacing issues (1) and (2) 
* 'cuckoo_task' allows to exploit the Task Hijacking issue (3)

Use the "--help" option for a more exhaustive explaination.

```
python3 taskHijacker.py --misconfig_task|--cuckoo_task <VICTIM-PACKAGE-NAME> -a <PATH/TO/YOUR/APK>.apk
```

Some examples below.

Launch taskHijacker using 'misconfig_task' exploitation mode, to turn the activity 'BadActivity' of 'your_harmless.apk' into a malicious activity 
able to exploit Task Hijacking issues (1) and (2) against the specified victim app 'com.victim.app'.  
```
python3 taskHijacker.py -m com.victim.app -e your.harmless.app.BadActivity -a /tmp/your_harmless.apk
```

Launch taskHijacker using 'cuckoo_task' exploitation mode, to turn the main activity (default) of 'your_harmless.apk' into a malicious activity 
able to exploit Task Hijacking issue (3) against the specified victim app 'com.victim.app'. 
```
python3 taskHijacker.py -c com.victim.app -a /tmp/your_harmless.apk
```

Launch taskHijacker with 'misconfig_task' exploitation mode, to turn the activity 'UglyActivity' of 'your_harmless.apk' into a malicious activity 
able to exploit Task Hijacking issues (1) and (2). And adopt the 'victim_screen.png' as background in the attacker APK on the folder 'res/drawable/' (default).
```
python3 taskHijacker.py -m com.victim.app -e UglyActivity -i /tmp/victim_screen.png -a /tmp/your_harmless.apk
```

Note that during the re-signing of the attacker APK, the script will ask you to provide the following information about the keystore to use:
* Keystore full-path
* Keystore password
* Keystore alias

Below an example of the script prompt filled with some keystore data:
```
...
[+] Starting the APK signing procedure, in order to continue a keystore is needed...
>>> Enter your keystore fullpath: /home/user/Downloads/objection-master/objection/utils/assets/objection.jks
>>> Enter your keystore password: XXXXXXXX
>>> Enter your keystore alias: objection
...
```



# Author
taskHijacker was developed by Maurizio Siddu


# GNU License
Copyright (c) 2024 taskHijacker

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
