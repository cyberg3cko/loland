from bs4 import BeautifulSoup
import requests
import json
import os
import time
from datetime import datetime

loldrivers = "https://www.loldrivers.io/api/drivers.json"
page = requests.get(loldrivers)
status = page.status_code
strf_date = datetime.today().strftime('%Y-%m-%d')
outfile = "{}_LOLDrivers.csv".format(strf_date[2:].replace("-",""))


def write_to_file(file_to_write, mode, content):
    if len(content) > 64:
        with open(file_to_write, mode) as loldrivers_csv:
            loldrivers_csv.write(content)


def main():
    if status == 200:
        write_to_file(outfile, "w", "driver_id,driver_tags,driver_verified,driver_created,driver_commands,kvs_filename,kvs_sha256,kvs_publisher,kvs_company,kvs_prodversion,kvs_fileversion,kvs_origfilename,kvs_imports,tbs_sha256\n")
        tdrivers = BeautifulSoup(page.content, "html.parser")
        jdrivers = json.loads(tdrivers.text)

        # cycling through each driver
        for driver in jdrivers:
            driver_id = driver["Id"]
            driver_tags = driver["Tags"]
            driver_verified = driver["Verified"]
            driver_created = driver["Created"]
            # checking for Commands
            try:
                if "Commands" in str(driver):
                    for command in driver["Commands"]:
                        if command == "Command":
                            driver_command = driver["Commands"]["Command"]
                            driver_commands = driver_command.replace(",","%2C")
                        else:
                            driver_commands = "-"
                else:
                    driver_commands = "-"
            except:
                pass
            for known_vulnerable_sample in driver["KnownVulnerableSamples"]:
                kvs_filename = known_vulnerable_sample["Filename"].lower()
                # checking for file SHA256 hash
                try:
                    if "SHA256" in str(known_vulnerable_sample):
                        kvs_sha256 = known_vulnerable_sample["SHA256"]
                    else:
                        kvs_sha256 = "-"
                except:
                    pass
                # checking for Publisher
                try:
                    if "Publisher" in str(known_vulnerable_sample):
                        kvs_publisher = known_vulnerable_sample["Publisher"]
                    else:
                        kvs_publisher = "-"
                except:
                    pass
                # checking for Company
                try:
                    if "Company" in str(known_vulnerable_sample):
                        kvs_company = known_vulnerable_sample["Company"]
                    else:
                        kvs_company = "-"
                except:
                    pass
                # checking for ProductVersion
                try:
                    if "ProductVersion" in str(known_vulnerable_sample):
                        kvs_prodversion = known_vulnerable_sample["ProductVersion"]
                    else:
                        kvs_prodversion = "-"
                except:
                    pass
                # checking for FileVersion
                try:
                    if "FileVersion" in str(known_vulnerable_sample):
                        kvs_fileversion = known_vulnerable_sample["FileVersion"]
                    else:
                        kvs_fileversion = "-"
                except:
                    pass
                # checking for OriginalFileName
                try:
                    if "OriginalFilename" in str(known_vulnerable_sample):
                        kvs_origfilename = known_vulnerable_sample["OriginalFilename"]
                    else:
                        kvs_origfilename = "-"
                except:
                    pass
                # checking for Imports
                try:
                    if "Imports" in str(known_vulnerable_sample):
                        kvs_imports = known_vulnerable_sample["Imports"]
                        kvs_imports = str(kvs_imports)[2:-2].replace("', '", ";")
                    else:
                        kvs_imports = "-"
                except:
                    pass
                """# checking for Authenti SHA256 hash
                try:
                    if "AuthentihashSHA256" in str(known_vulnerable_sample):
                        kvs_authenti_sha256 = known_vulnerable_sample["AuthentihashSHA256"]
                    elif "Authentihash" in str(known_vulnerable_sample):
                        kvs_authenti_sha256 = known_vulnerable_sample["Authentihash"]["SHA256"]
                    else:
                        kvs_authenti_sha256 = "-"
                except:
                    pass"""
                # checking for TBS SHA256 hash
                try:
                    if "Signatures" in known_vulnerable_sample:
                        for signature in known_vulnerable_sample["Signatures"]:
                            if "TBS" in str(signature):
                                for certifcate in signature["Certificates"]:
                                    if "TBS" in str(certifcate):
                                        tbs_sha256 = certifcate["TBS"]["SHA256"]
                                    else:
                                        tbs_sha256 = "-"
                            else:
                                tbs_sha256 = "-"
                    elif "Signature" in known_vulnerable_sample:
                        for signature in known_vulnerable_sample["Signature"]:
                            if "TBS" in str(signature):
                                for certifcate in signature["Certificates"]:
                                    if "TBS" in str(certifcate):
                                        tbs_sha256 = certifcate["TBS"]["SHA256"]
                                    else:
                                        tbs_sha256 = "-"
                            else:
                                tbs_sha256 = "-"
                    else:
                        tbs_sha256 = "-"
                except:
                    pass
                # writing output to csv file
                if len(driver_tags) > 0 and ".sys" in str(driver_tags):
                    for driver_tag in driver_tags:
                        if driver_tag.endswith(".sys"):
                            loldrivers_row = "{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(driver_id, driver_tag, driver_verified, driver_created, driver_commands, kvs_filename, kvs_sha256, kvs_publisher, kvs_company, kvs_prodversion, kvs_fileversion, kvs_origfilename, kvs_imports, tbs_sha256)
                            write_to_file("."+outfile, "a", loldrivers_row)
                else:
                    loldrivers_row = "{},-,{},{},{},{},{},{},{},{},{},{}\n".format(driver_id, driver_verified, driver_created, driver_commands, kvs_filename, kvs_sha256, kvs_publisher, kvs_company, kvs_prodversion, kvs_fileversion, kvs_origfilename, kvs_imports, tbs_sha256)
                    write_to_file("."+outfile, "a", loldrivers_row)
    else:
        print("\n\t{} status code received: unable to collect LOLDrivers.\n".format(str(status)))

    if os.path.exists("."+outfile):
        with open("."+outfile) as temp:
            lines = temp.readlines()
            lines = list(set(lines))
        for line in lines:
            write_to_file(outfile, "a", line)


if __name__ == "__main__":
    main()
