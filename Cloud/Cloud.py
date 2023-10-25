# -*- coding: utf-8 -*-
import urllib2
import re
import time
from burp import IScanIssue, IScannerCheck, ITab, IHttpService, IHttpRequestResponse, IParameter, IParameter, IBurpExtender
from java.io import PrintWriter
from javax.swing import JPanel, JLabel, JCheckBox, JTextField, JButton, JFileChooser
from payloads import payloads
from sql_payloads import sql_payloads
from crlf_payloads import crlf_payloads
from code_injection_payload import code_injection_payloads
from XXE_payloads import XXE_payloads
from rfi_payloads import rfi_payloads
from java.net import URLDecoder
import os

class CloudScanner(IScannerCheck):

    def check_insecure_headers(self, url, response):
        insecure_headers = []

        # Проверка заголовков на наличие небезопасных настроек
        headers = response.getHeaders()

        # Проверка наличия заголовка X-Frame-Options
        if "X-Frame-Options" not in response.headers:
            insecure_headers.append("X-Frame-Options отсутствует")

        # Проверка наличия заголовка Content-Security-Policy
        if "Content-Security-Policy" not in response.headers:
            insecure_headers.append("Content-Security-Policy отсутствует")

        # Проверка наличия заголовка Strict-Transport-Security
        if "Strict-Transport-Security" not in response.headers:
            insecure_headers.append("Strict-Transport-Security отсутствует")

        if insecure_headers:
            issue = CustomScanIssue(
                self._helpers.buildHttpService(url),
                [self._callbacks.applyMarkers(response, None, None)],
                "Insecure Headers",
                "The response contains insecure headers:\n{}".format("\n".join(insecure_headers)),
                "Medium",
                "Certain"
            )
            return insecure_headers

        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint, url, emails):

        # Проверка небезопасных заголовков
        response = baseRequestResponse.getResponse()
        insecure_headers = self.check_insecure_headers(
            baseRequestResponse.getHttpService().getProtocol() + "://" + baseRequestResponse.getHttpService().getHost(),
            response
        )

        return insecure_headers

class WebsiteChangeMonitor:
    def __init__(self, target_url):
        self.target_url = target_url
        self.previous_content = None

    def check_for_changes(self):
        response = self.send_get_request(self.target_url)
        if response is not None and response.code == 200:
            current_content = response.read()
            if self.previous_content is not None and current_content != self.previous_content:
                print("[+] Website content has changed!")
                # Отправьте уведомление о изменениях
            self.previous_content = current_content

    def send_get_request(self, url):
        try:
            response = self.opener.open(url)
            return response
        except Exception as e:
            print("Error sending GET request: {}".format(e))
            return None

class CustomPayloadLoader: #загрузка кастомного Payload
    @staticmethod
    def select_custom_payloads():
        file_chooser = JFileChooser()
        file_chooser.setDialogTitle("Select Custom Payloads")
        file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)
        file_chooser.setMultiSelectionEnabled(False)

        return_code = file_chooser.showOpenDialog(None)
        if return_code == JFileChooser.APPROVE_OPTION:
            selected_file = file_chooser.getSelectedFile()
            return selected_file.getAbsolutePath()
        else:
            return None

    @staticmethod
    def load_custom_payloads(file_path):
        try:
            with open(file_path, 'r') as file:
                payloads = file.readlines()
                return [payload.strip() for payload in payloads]
        except Exception as e:
            print("Error loading custom payloads: {}".format(e))
            return []

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, httpMessages, name, detail, severity, confidence):
        self._httpService = httpService
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity
        self._confidence = confidence

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService

    def getIssueDetail(self):
        return self._detail

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return self._confidence

class DataLeakScanner(IScannerCheck):
    def __init__(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

    def find_leaks(response_text):
        leaks = []

        # Поиск API-ключей
        api_key_pattern = r'[0-9a-fA-F]{32}'
        api_keys = re.findall(api_key_pattern, response_text)
        leaks.extend(api_keys)

        # Поиск паролей
        password_pattern = r'(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}'
        passwords = re.findall(password_pattern, response_text)
        leaks.extend(passwords)

        # Поиск адресов электронной почты
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b'
        emails = re.findall(email_pattern, response_text)
        leaks.extend(emails)

        return leaks

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        # Получаем запрос
        request = baseRequestResponse.getRequest()
        analyzedRequest = self._helpers.bytesToString(request)

        # Получаем ответ
        response = baseRequestResponse.getResponse()
        analyzedResponse = self._helpers.bytesToString(response)

        # Вызываем функцию для обнаружения утечек
        leaks = self.find_leaks(analyzedResponse)

        if leaks:
            self._callbacks.addScanIssue(
                CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                    "Data Leak Vulnerability",
                    "Potential data leak found",
                    "High",
                    "Certain"
                )
            )

            # Наличие утечек данных в файлах cookie
            requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
            requestHeaders = requestInfo.getHeaders()
            cookies = [header for header in requestHeaders if header.startswith("Cookie: ")]
            if cookies:
                cookies = cookies[0][8:].split("; ")

                for cookie in cookies:
                    cookieParts = cookie.split("=")
                    if len(cookieParts) == 2:
                        cookieName = URLDecoder.decode(cookieParts[0], "UTF-8")
                        cookieValue = URLDecoder.decode(cookieParts[1], "UTF-8")

                        # Проверка конфиденциальных данных
                        if "confidential_data" in cookieValue:
                            issue = CustomScanIssue(
                                baseRequestResponse.getHttpService(),
                                [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                                "Cookie Data Leak",
                                "Potential data leak found in cookie: {}={}".format(cookieName, cookieValue),
                                "High",
                                "Certain"
                            )
                            return [issue]
        return None

class XssScanner:
    def __init__(self, emails, url):  # Add 'url' as a parameter in the constructor
        self.test_mode = (self.test_mode)
        self.opener = urllib2.build_opener()
        self.check_rfi = (self.url)
        self._helpers = (self.helpers)
        self.opener = urllib2.build_opener()
        self._callbacks = (self._callbacks)
        self._callbacks = (self.callbacks)
        self.url = url  # Initialize 'url' attribute with the provided value
        self.emails = emails
        self.credit_card = True

    def check_insecure_downloads(self, url, response):
        # Проведите анализ ответа на предмет признаков небезопасной загрузки
        insecure_downloads = []

        # Пример: Проверка на использование HTTP вместо HTTPS
        if "http://" in response:
            insecure_downloads.append("Insecure HTTP download detected")

        if insecure_downloads:
            issue = CustomScanIssue(
                self._helpers.buildHttpService(url),
                [self._callbacks.applyMarkers(response, None, None)],
                "Insecure Download Vulnerability",
                "\n".join(insecure_downloads),
                "High",
                "Certain"
            )
            return [issue]

        return None

    def check_malicious_file_extensions(self, url, response):
        # Проверка на наличие опасных файловых расширений
        dangerous_extensions = ['.exe', '.dll', '.bat', '.vbs', '.ps1']
        parsed_url = urlparse(url)
        file_path = parsed_url.path
        file_extension = os.path.splitext(file_path)[1]

        if file_extension in dangerous_extensions:
            issue = CustomScanIssue(
                self._helpers.buildHttpService(url),
                [self._callbacks.applyMarkers(response, None, None)],
                "Malicious File Extension",
                "The response contains a potential malicious file extension ({})".format(file_extension),
                "High",
                "Certain"
            )
            return [issue]
        return None

    def check_content_disposition(self, url, response):
        # Проверка заголовка Content-Disposition на наличие опасных приложений
        content_disposition = response.getHeader('Content-Disposition')

        if content_disposition and 'attachment' in content_disposition.lower():
            issue = CustomScanIssue(
                self._helpers.buildHttpService(url),
                [self._callbacks.applyMarkers(response, None, None)],
                "Unsafe Content-Disposition",
                "The response contains a potentially unsafe Content-Disposition header",
                "Medium",
                "Certain"
            )
            return [issue]
        return None

    def send_request(self, url, method, data=None):
        try:
            if method == "GET":
                response = self.opener.open(url)
            elif method == "POST":
                if data:
                    response = self.opener.open(url, data)
                else:
                    response = self.opener.open(url)
            elif method == "PUT":
                if data:
                    response = self.opener.request('PUT', url, data=data)
                else:
                    response = self.opener.open(url, method='PUT')
            elif method == "DELETE":
                if data:
                    response = self.opener.request('DELETE', url, data=data)
                else:
                    response = self.opener.open(url, method='DELETE')
            else:
                raise ValueError("Unsupported HTTP method: {}".format(method))

            return response
        except Exception as e:
            print("Error sending {} request: {}".format(method, e))
            return None

    def send_get_request(self, url):
        try:
            response = self.opener.open(url)
            return response
        except Exception as e:
            print("Error sending GET request: {}".format(e))
            return None

    def find_links_on_page(self, url):
        response = self.send_get_request(url)
        if response is not None and response.code == 200:
            try:
                content = response.read()
                links = re.findall(r'href=[\'"]?([^\'" >]+)', content)
                return links
            except Exception as e:
                return str(e)
        return []

    def check_xxe_49(self, url, response):
            # Проведите анализ ответа на предмет признаков XXE
            if "XXE Indicator" in response:
                issue = CustomScanIssue(
                    self._helpers.buildHttpService(url),
                    [self._callbacks.applyMarkers(response, None, None)],
                    "XXE Vulnerability",
                    "The response contains a potential XXE vulnerability",
                    "High",
                    "Certain"
                )
                return [issue]
            return None

    def check_sql_injection(self, url, response):
            # Проведите анализ ответа на предмет признаков SQL-инъекции
            if "SQL syntax error" in response:
                issue = CustomScanIssue(
                    self._helpers.buildHttpService(url),
                    [self._callbacks.applyMarkers(response, None, None)],
                    "SQL Injection Vulnerability",
                    "The response contains a potential SQL injection vulnerability",
                    "High",
                    "Certain"
                )
                return [issue]
            return None

    def test_sql_injection(self, url):
            for payload in sql_payloads:
                modified_url = url + "?id=" + urllib2.quote(payload)
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                    self.check_sql_injection(modified_url, response.read())

    def check_crlf_injection(self, url, response):
        for payload in crlf_payloads:
            modified_url = url + payload
            response = self.send_get_request(modified_url)
            if response is not None and response.code == 200:
                # Проверка на CRLF-инъекцию
                if "test=test" in response.read():
                    issue = CustomScanIssue(
                        self._helpers.buildHttpService(modified_url),
                        [self._callbacks.applyMarkers(response, None, None)],
                        "CRLF Injection Vulnerability",
                        "The response contains a potential CRLF injection vulnerability",
                        "High",
                        "Certain"
                    )
                    return [issue]
        return None

    def test_crlf_injection(self, url):
            for payload in crlf_payloads:
                modified_url = url + "?id=" + urllib2.quote(payload)
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                    self.check_crlf_injection(modified_url, response.read())

    def check_code_injection(self, url):
            for payload in code_injection_payloads:
                modified_url = url + payload
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                    # Проверка на инъекцию кода
                    if "49" in response.read():
                        issue = CustomScanIssue(
                            self._helpers.buildHttpService(modified_url),
                            [self._callbacks.applyMarkers(response, None, None)],
                            "Code Injection Vulnerability",
                            "The response contains a potential code injection vulnerability",
                            "High",
                            "Certain"
                        )
                        return [issue]
                return None

    def test_code_injection(self, url):
            for payload in crlf_payloads:
                modified_url = url + "?id=" + urllib2.quote(payload)
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                    self.check_code_injection(modified_url, response.read())

    def check_xxe_code_injection(self, url, response):
        for payload in XXE_payloads:
            modified_url = url + payload
            response = self.send_get_request(modified_url)
            if response is not None and response.code == 200:
                if "49" in response.read():
                    issue = CustomScanIssue(
                        self._helpers.buildHttpService(modified_url),
                        [self._callbacks.applyMarkers(response, None, None)],
                        "Code XXE Vulnerability",
                        "The response contains a potential code injection vulnerability",
                        "High",
                        "Certain"
                    )
                    return [issue]
            return None

    def test_xxe_code_injection(self, url):
        for payload in XXE_payloads:
            modified_url = url + "?id=" + urllib2.quote(payload)
            response = self.send_get_request(modified_url)
            if response is not None and response.code == 200:
                self.check_code_injection(modified_url, response.read())

    def check_rfi(self, url):
        for payload in rfi_payloads:
            modified_url = url + payload
            response = self.send_get_request(modified_url)
            if response is not None and response.code == 200:
                # Проверка на удаленное включение файлов
                if "RFI Indicator" in response.read():
                    issue = CustomScanIssue(
                        self._helpers.buildHttpService(modified_url),
                        [self._callbacks.applyMarkers(response, None, None)],
                        "RFI Vulnerability",
                        "The response contains a potential RFI vulnerability",
                        "High",
                        "Certain"
                    )
                    return [issue]
        return None

    def test_rfi(self, url):
            for payload in rfi_payloads:
                modified_url = url + "?id=" + urllib2.quote(payload)
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                    self.check_rfi(modified_url, response.read())

    def doPassiveScan(self, baseRequestResponse):
        # Получаем ответ
        response = baseRequestResponse.getResponse()
        analyzedResponse = self._helpers.bytesToString(response)


        # Получаем куки из запроса
        requestInfo = self._helpers.analyzeRequest(baseRequestResponse)
        requestHeaders = requestInfo.getHeaders()
        cookies = [header for header in requestHeaders if header.startswith("Cookie: ")]
        if cookies:
            cookies = cookies[0][8:].split("; ")  # Extract and split the cookies

            # Check each cookie for potential data leaks
            for cookie in cookies:
                cookieParts = cookie.split("=")
                if len(cookieParts) == 2:
                    cookieName = URLDecoder.decode(cookieParts[0], "UTF-8")
                    cookieValue = URLDecoder.decode(cookieParts[1], "UTF-8")

                    # Placeholder condition for checking confidential data
                    if "confidential_data" in cookieValue:
                        issue = CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            [self._callbacks.applyMarkers(baseRequestResponse, None, None)],
                            "Cookie Data Leak",
                            "Potential data leak found in cookie: {}={}".format(cookieName, cookieValue),
                            "High",
                            "Certain"
                        )
                        return [issue]

        return None

        def anomaly_detection(data):
            mean = sum(data) / len(data)
            variance = sum((x - mean) ** 2 for x in data) / len(data)
            std_dev = variance ** 0.5

            anomalies = []
            threshold = 3  # Порог для определения аномалий

            for x in data:
                z_score = (x - mean) / std_dev
                if abs(z_score) > threshold:
                    anomalies.append(x)

            return anomalies

        def get_data_from_response(response_data):
            # Используем регулярное выражение для поиска всех чисел
            data = re.findall(r'\d+', response_data)
            # Преобразуем найденные строки в целые числа
            data = [int(d) for d in data]
            return data

        data = get_data_from_response(analyzedResponse)

        anomalies = anomaly_detection(data)

        if anomalies:
            self.stdout.println("[+] Найдены аномалии:")
            for anomaly in anomalies:
                self.stdout.println("    - %s" % anomaly)

            # Отмечаем аномалии в запросе/ответе
            return [self._callbacks.applyMarkers(baseRequestResponse, None, None)]

        # Получаем состояние чекбоксов
        search_credit_cards = self.credit_card.isSelected()
        search_emails = self.emails.isSelected()

        # Получаем состояние чекбокса тестового режима
        test_mode = self.test_mode.isSelected()

        # Задаем шаблон для поиска утечек
        leak_pattern = ''
        if search_credit_cards:
            leak_pattern += r'\b(?:\d[ -]*?){13,16}\b'
        if search_emails:
            leak_pattern += r'|(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b)'

        # Ищем совпадения
        leaks = re.findall(leak_pattern, analyzedResponse)

        if leaks:
            self.stdout.println("[+] Найдены потенциальные утечки данных:")
        for leak in leaks:
            self.stdout.println("    - %s" % leak)
            if test_mode:
                with open("leaks_test.txt", "a") as file:
                    for leak in leaks:
                        file.write("Potential data leak found: %s\n" % leak)
            else:
                with open("leaks.txt", "a") as file:
                    for leak in leaks:
                        file.write("Potential data leak found: %s\n" % leak)

            return [self._callbacks.applyMarkers(baseRequestResponse, None, None)]

        return None

    def doActiveScan(self, baseRequestResponse, insertionPoint, url, emails, responce):
        request = baseRequestResponse.getRequest()
        analyzedRequest = self._helpers.bytesToString(request)
        analyzedResponse = self._helpers.bytesToString(response)

        # Вызываем проверку небезопасных загрузок

        insecure_downloads = self.check_insecure_downloads(
            baseRequestResponse.getHttpService().getProtocol() + "://" + baseRequestResponse.getHttpService().getHost(),
            analyzedResponse)

        if insecure_downloads:
            return insecure_downloads

        # Define 'issues' as an empty list
        issues = []

        # Call check_content_disposition
        issues += self.check_content_disposition(url, response)

        # Call check_malicious_file_extensions
        issues += self.check_malicious_file_extensions(url, response)

        return issues

        self.check_rfi = (self.url)
        scanner = XssScanner(emails)
        scanner.doActiveScan(baseRequestResponse, insertionPoint, "http://example.com")

        # Отправка POST-запроса
        data = "param1=value1&param2=value2"  # Подставьте свои данные
        response = scanner.send_request("http://example.com", "POST", data)

        if response:

            # Пример анализа тела ответа
            response_body = response.text
            if "some_pattern" in response_body:
                # Если в теле ответа есть какой-то паттерн, то выполните какие-то действия
                pass

            # Пример проверки статус кода ответа
            if response.status_code == 200:
                print("POST Active")
                # Если статус код равен 200, то выполните какие-то действия
                pass

        # Отправка GET-запроса
        response = scanner.send_request("http://example.com", "GET")

        if response:
            response_body = response.text
            if "some_pattern" in response_body:
                # Если в теле ответа есть какой-то паттерн, то выполните какие-то действия
                pass

            # Пример проверки статус кода ответа
            if response.status_code == 200:
                print("GET Active")
                # Если статус код равен 200, то выполните какие-то действия
                pass

        for payload in payloads:
            modifiedRequest = analyzedRequest.replace(insertionPoint.getInsertionPoint(), payload)
            newRequest = self._helpers.stringToBytes(modifiedRequest)

            newResponse = self._callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest)
            response = newResponse.getResponse()
            analyzedResponse = self._helpers.bytesToString(response)

            if "<script>alert('XSS')</script>" in analyzedResponse:
                issue = CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    [self._callbacks.applyMarkers(newResponse, None, None)],
                    "XSS Vulnerability",
                    "The response contains a potential XSS vulnerability",
                    "High",
                    "Certain"
                )

            for payload in XXE_payloads:
                modified_url = baseRequestResponse.getHttpService().getProtocol() + "://" + baseRequestResponse.getHttpService().getHost() + baseRequestResponse.getHttpService().getPath() + "?id=" + urllib2.quote(payload)
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                        # Check for XXE injection
                    if "49" in response.read():
                        issue = CustomScanIssue(
                            self._helpers.buildHttpService(modified_url),
                            [self._callbacks.applyMarkers(response, None, None)],
                            "Code XXE Vulnerability",
                            "The response contains a potential code injection vulnerability",
                            "High",
                            "Certain"
                            )
                    return [issue]

            for payload in rfi_payloads:
                modified_url = self.url + "?id=" + urllib2.quote(payload)
                response = self.send_get_request(modified_url)
                if response is not None and response.code == 200:
                    # Проверка на удаленное включение файлов
                    if "RFI Indicator" in response.read():
                        issue = CustomScanIssue(
                            self._helpers.buildHttpService(modified_url),
                            [self._callbacks.applyMarkers(response, None, None)],
                            "RFI Vulnerability",
                            "The response contains a potential RFI vulnerability",
                            "High",
                            "Certain"
                        )
                        return [issue]

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        if existingIssue.getIssueName() == newIssue.getIssueName():
            return -1
        else:
            return 0

class BurpExtender(IBurpExtender, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("CloudScanner")
        self.change_monitor = WebsiteChangeMonitor("http://example.com")

        # Создаем GUI
        self.tab = JPanel()
        self.test_mode = JCheckBox("Test Mode", False)
        self.tab.add(self.test_mode)
        self.credit_card = JCheckBox("Credit cards", False)
        self.emails = JCheckBox("Email", False)
        self.tab.add(self.credit_card)
        self.tab.add(self.emails)


        # Добавляем кнопку для загрузки пользовательских пэйлоадов
        self.custom_payload_button = JButton("Load Custom Payloads", actionPerformed=self.load_custom_payloads)
        self.tab.add(self.custom_payload_button)

        callbacks.customizeUiComponent(self.tab)
        callbacks.addSuiteTab(self)

    def run(self):
        while True:
            # Проверяем изменения каждые 5 минут (или в другом удобном вам интервале)
            time.sleep(300)
            self.change_monitor.check_for_changes()

    def load_custom_payloads(self, event):
        custom_payload_file_path = CustomPayloadLoader.select_custom_payloads()

        if custom_payload_file_path:
            custom_payloads = CustomPayloadLoader.load_custom_payloads(custom_payload_file_path)


    def getTabCaption(self):
        return "CloudScanner"

    def getUiComponent(self):
        return self.tab

    def accept(self, f):
        if f.isDirectory():
            return True
        return f.getName().lower().endswith(self.extension)

    def getDescription(self):
        return self.description