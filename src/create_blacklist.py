######################### Create Blacklist from VirusTotal  ######################
# How to run:
#     First, isolate domain data from DNS queries and write it to a new file (cat <file> | awk -F '\t' '{print $10 "\t"}' > <newfile>)
#     Make sure to add a new line to the end of new domain data file to ensure proper function
#     Use this new file as the input file for create_blacklist.py, ex. Python3 create_blacklist.py --inputfile newfile
#     Add your VirusTotal API key to the API key variable
#     VirusTotal Public API only allows for 500 queries a day and 4/minute so you may run into issues if you try to do more 


import argparse
import requests
import json
import time

API_KEY = ''


def main():
    # Process command line arguments
    parser = argparse.ArgumentParser()
    parser.add_argument('--inputfile', type=str, required=True, help="The dns record file")
    FLAGS = parser.parse_args()
    queried_domains = []
    malicious_domains = []

    
    #clean_data(FLAGS.inputfile) TODO should move data cleaning into separate function

    # Open a file with the queried domains
    with open(FLAGS.inputfile, "r") as infile:
        for line in infile:
            domain_query = line[:-1] #removes \n
            if(domain_query == "-" or domain_query == "(empty)"): #Doesn't query for lines in the file with no domain data
                pass
                print("made it")
            else:
                virustotal_url = 'https://www.virustotal.com/vtapi/v2/url/report'
                params = {'apikey': API_KEY, 'resource':domain_query}
                response = requests.post(virustotal_url, params=params)
                data = response.json()
                #print(data["positives"])
                if(data["response_code"] == 0): #if the query does not exist in data, it returns 0
                    pass
                elif(data["positives"] == 0): #if no one has marked the domain as malicious, positives = 0
                    pass
                else:
                    malicious_domains.append(domain_query)
                    print(malicious_domains)
                    with open("blacklist2.json", "w", encoding='utf-8') as f:
                        json.dump(malicious_domains, f, ensure_ascii=False, indent=4)
                time.sleep(20) #so as not to send more than 4 queries a minute
       

main()

'''
VirusTotal API for domain reports:

    url = 'https://www.virustotal.com/vtapi/v2/url/report'


    params = {'apikey': '<apikey>', 'resource':'<url>'}


    response = requests.post(url, params=params)


    print(response.json())

'''
