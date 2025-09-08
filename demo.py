import requests


def claimcar():
    url = "http://xxx.xxx.xxx.xxx/claimcar/api/applicationLayer/piccclaim/newFrame/bpm/viewFlowChart"
    headers = {
        "Authorization": authorization,
        "Cookie": cookie,
        "comcode": "",  # 公司代码
        "sysnum": "CXLP"
    }
    data = {
        "registNo": "",  # 报案号
        "userCodeSession": "",  # 工号
        "userNameSession": "",  # 用户名
        "comCodeSession": ""  # 固定值
    }

    response = requests.post(url, headers=headers, json=data)
    response.encoding = 'utf-8'
    nodePKVoList = response.json()['data']['nodePKVoList']
    for node in nodePKVoList:
        nodeAddVo = node['nodeAddVo']
        print(nodeAddVo['nodeName'], nodeAddVo['stat'])

def comcode():
    url = f"http://xxx.xxx.xxx.xxx/newFrame/registApi/processQuery"
    headers = {
        "Authorization": authorization,
        "Cookie": cookie
    }
    data = {
        "comCode": "",  # 公司代码
        "queryFlag": "1",
        "carPageNo": "1",
        "carPageSize": "50",
        "noCarPageNo": "1",
        "noCarPageSize": "50"
    }
    
    response = requests.post(url, headers=headers, json=data)
    response.encoding = "utf-8"
    comCode = response.json()["data"]["carCaseInfoList"][0]["comCode"]
    print(comCode)


if __name__ == '__main__':
    authorization = ""
    cookie = ""
    claimcar()
    comcode()
