from enum import Enum
import csv


def is_support_wechat_login(keyword):
    wechat = ["weixin", "wechat", "wx_login", "iv_wx", "login_wx"]
    for wx in wechat:
        if wx in keyword:
            print(f"Support Wechat Login: **[{keyword}]**")
            return True
    return False

class AppStatus(Enum):
    OPEN_ERROR        = -30
    LOGIN_NOT_SUPPORT = -20
    LOGIN_FAILURE     = -10
    LOGIN_SUCCESS     = 10


class LoginType(Enum):
    LOGIN_BY_PHONE  = 1
    LOGIN_BY_WECHAT = 2
    LOGIN_BY_QQ     = 3
    LOGIN_BY_WEIBO  = 4
    LOGIN_UNKNOWN   = 100
    

class Login():
    def __init__(self, apk_name):
        self.apk_name = apk_name
        self.login_status = AppStatus.LOGIN_NOT_SUPPORT
        self.is_support = False
        self.login_type = LoginType.LOGIN_UNKNOWN

    def is_login_success(self):
        return self.login_status == AppStatus.LOGIN_SUCCESS

    def is_login_failed(self):
        return self.login_status == AppStatus.LOGIN_FAILURE

    
    def set_login_success(self, find_login_btn=True):
        if self.is_support and find_login_btn:
            self.login_status = AppStatus.LOGIN_SUCCESS

    def set_login_failed(self):
        if self.is_support and self.login_status != AppStatus.LOGIN_SUCCESS:
            self.login_status = AppStatus.LOGIN_FAILURE

    def is_support():
        return self.is_support

    def set_open_failed(self):
        if self.login_status == AppStatus.LOGIN_NOT_SUPPORT:
            self.login_status = AppStatus.OPEN_ERROR

    
    def write_login_data(self):
        with open("out/login_status.csv", "a") as f:
            writer = csv.writer(f)
            writer.writerow([self.apk_name, self.login_status])


class WechatLogin(Login):
    def __init__(self, apk_name):
        super().__init__(apk_name)
        self.login_type = LoginType.LOGIN_BY_WECHAT
        self.is_support = True
