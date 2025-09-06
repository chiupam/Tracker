import requests


def main():
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


if __name__ == '__main__':
    authorization = ""
    cookie = ""
    main()
