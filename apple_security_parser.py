import requests
from bs4 import BeautifulSoup
from lxml import etree
import json
import csv
from tqdm import tqdm

url = 'https://support.apple.com/en-us/HT201222'
links = []

res = requests.get(url)
html = res.text
soup = BeautifulSoup(html, 'html.parser')
body = soup.find('body')
dom = etree.HTML(str(body))

information = {"version":"", "link":""}

for i in range(2000):
    xpath = f'//*[@id="tableWraper"]/table/tbody/tr[{i}]/td[1]/a'
    if dom.xpath(xpath) != []:
        version = dom.xpath(xpath)[0].text
        if version.find('iOS') != -1:
            information["version"] = version
            information["link"] = dom.xpath(xpath)[0].attrib['href']
            links.append(information.copy())

print(links)

dir = {
    "Target": "",
    "Impact": "",
    "Description": "",
    "CVE": [],
    "Version": "",
}

dir_list = []

for link in tqdm(links):
    url = link['link']

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
                tmp_dir["Target"] = target
                tmp_dir["CVE"] = []
                tmp_dir["Version"] = link['version']

            xpath2 = f'//*[@id="sections"]/div[3]/div/p[{idx}]/text()'
            if dom.xpath(xpath2) != []:
                p_tag = dom.xpath(xpath2)[0]
            
                if p_tag != None:
                    if p_tag.find("Impact") != -1:
                        tmp_dir["Impact"] = p_tag.replace("Impact:", "").strip()
                    elif p_tag.find("Description") != -1:
                        tmp_dir["Description"] = p_tag.replace("Description:", "").strip()
                    elif p_tag.find("CVE") != -1:
                        tmp_dir["CVE"].append(p_tag.split(':')[0].strip())
            
        if tmp_dir:
            dir_list.append(tmp_dir)

with open(f'go.csv', 'w', newline='', encoding='utf-8') as csvfile:
    fieldnames = ['Target', 'Impact', 'Description', 'CVE', 'Version']
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

    writer.writeheader()
    for data in dir_list:
        writer.writerow(data)
