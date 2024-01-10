import requests
from bs4 import BeautifulSoup
from lxml import etree
import json
import csv

dir = {
    "target": "",
    "Impact": "",
    "Description": "",
    "CVE": [],
}

dir_list = []

sub = 'HT213938'
url = f'https://support.apple.com/en-us/{sub}'

response = requests.get(url)

if response.status_code == 200:
    html = response.text
    soup = BeautifulSoup(html, 'html.parser')
    body = soup.find('body')
    dom = etree.HTML(str(body))
    tmp_dir = None
    for idx in range(1000):
        xpath = f'//*[@id="sections"]/div[3]/div/p[{idx}]/strong'
        if dom.xpath(xpath) != []:
            if tmp_dir:
                dir_list.append(tmp_dir)
            tmp_dir = dir.copy()
            target = dom.xpath(xpath)[0].text
            tmp_dir["target"] = target
            tmp_dir["CVE"] = []

        xpath2 = f'//*[@id="sections"]/div[3]/div/p[{idx}]/text()'
        if dom.xpath(xpath2) != []: # and dom.xpath(xpath2)[0].text != None:
            p_tag = dom.xpath(xpath2)[0] # .text
        
            if p_tag != None:
                if p_tag.find("Impact") != -1:
                    tmp_dir["Impact"] = p_tag.replace("Impact: ", "").strip()
                elif p_tag.find("Description") != -1:
                    tmp_dir["Description"] = p_tag.replace("Description: ", "").strip()
                elif p_tag.find("CVE") != -1:
                    tmp_dir["CVE"].append(p_tag.split(':')[0].strip())
        
    if tmp_dir:
        dir_list.append(tmp_dir)

    print(dir_list)

with open(f'{sub}.csv', 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['target', 'Impact', 'Description', 'CVE']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for data in dir_list:
        writer.writerow(data)
