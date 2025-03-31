from bs4 import BeautifulSoup
import requests
import json
import time
from datetime import datetime

loldrivers = "https://www.loldrivers.io/api/drivers.json"
page = requests.get(loldrivers)
status = page.status_code
strf_date = datetime.today().strftime('%Y-%m-%d')
outfile = "{}_LOLDrivers.csv".format(strf_date[2:].replace("-",""))

def main():
    if status == 200:
        with open(outfile, "w") as loldrivers_csv:
            loldrivers_csv.write("driver_id,kvs_filename,kvs_tag,kvs_sha256,kvs_authenti_sha256,tbs_sha256\n")
        tdrivers = BeautifulSoup(page.content, "html.parser")
        jdrivers = json.loads(tdrivers.text)

        # cycling through each driver
        for driver in jdrivers:
            driver_id = driver["Id"]
            tags = driver["Tags"]
            for known_vulnerable_sample in driver["KnownVulnerableSamples"]:
                kvs_filename = known_vulnerable_sample["Filename"].lower()

                # checking for file SHA256 hash
                if "SHA256" in str(known_vulnerable_sample):
                    kvs_sha256 = known_vulnerable_sample["SHA256"]
                else:
                    kvs_sha256 = "-"

                # checking for Authenti SHA256 hash
                if "AuthentihashSHA256" in str(known_vulnerable_sample):
                    kvs_authenti_sha256 = known_vulnerable_sample["AuthentihashSHA256"]
                elif "Authentihash" in str(known_vulnerable_sample):
                    kvs_authenti_sha256 = known_vulnerable_sample["Authentihash"]["SHA256"]
                else:
                    kvs_authenti_sha256 = "-"

                # checking for TBS SHA256 hash
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

                # writing output to csv file
                if len(tags) > 0 and ".sys" in str(tags):
                    for tag in tags:
                        if tag.endswith(".sys"):
                            loldrivers_row = "{},{},{},{},{},{}\n".format(driver_id, kvs_filename, tag.lower(), kvs_sha256, kvs_authenti_sha256, tbs_sha256)
                            if len(loldrivers_row) > 40:
                                with open(outfile, "a") as loldrivers_csv:
                                    loldrivers_csv.write(loldrivers_row)
                else:
                    loldrivers_row = "{},{},-,{},{},{}\n".format(driver_id, kvs_filename, kvs_sha256, kvs_authenti_sha256, tbs_sha256)
                    if len(loldrivers_row) > 40:
                        with open(outfile, "a") as loldrivers_csv:
                            loldrivers_csv.write(loldrivers_row)


if __name__ == "__main__":
    main()
