import requests
import json
import uuid
import platform
import hashlib

class UserStore:
    def fetchUser(self):
        # 模拟获取用户信息
        print("Fetching user information...")

class AuthClient:
    def __init__(self, base_url):
        self.base_url = base_url
        self.stage = 'find-account'
        self.error = None
        self.account_identifier = ''
        self.device_id = ''
        self.challenge = None
        self.factors = []
        self.selected_factor_id = None
        self.password = ''
        self.user_store = UserStore()

    def generate_device_id(self):
        # 使用platform和uuid模块生成设备指纹
        platform_info = platform.system() + platform.release() + platform.machine()
        unique_id = uuid.getnode()
        device_info = f"{platform_info}-{unique_id}"
        # 使用SHA-256哈希生成设备ID
        self.device_id = hashlib.sha256(device_info.encode()).hexdigest()

    def handle_find_account(self):
        if not self.account_identifier:
            self.error = 'Please enter your email or username.'
            return

        self.error = None
        try:
            response = requests.post(
                f"{self.base_url}/api/auth/challenge",
                headers={'Content-Type': 'application/json'},
                data=json.dumps({
                    'platform': 1,
                    'account': self.account_identifier,
                    'device_id': self.device_id,
                })
            )
            if not response.ok:
                raise Exception(response.text or 'Account not found.')

            self.challenge = response.json()
            self.get_factors()
            self.stage = 'select-factor'
        except Exception as e:
            self.error = str(e)

    def get_factors(self):
        self.error = None
        try:
            response = requests.get(
                f"{self.base_url}/api/auth/challenge/{self.challenge['id']}/factors"
            )
            if not response.ok:
                raise Exception('Could not fetch authentication factors.')

            available_factors = response.json()
            self.factors = [factor for factor in available_factors if factor['id'] not in self.challenge['blacklist_factors']]
            if len(self.factors) > 0:
                self.selected_factor_id = None  # 让用户选择
            elif self.challenge['step_remain'] > 0:
                self.error = 'No more available authentication factors, but authentication is not complete. Please contact support.'
        except Exception as e:
            self.error = str(e)

    def request_verification_code(self, hint):
        if not self.selected_factor_id:
            return

        self.error = None
        try:
            response = requests.post(
                f"{self.base_url}/api/auth/challenge/{self.challenge['id']}/factors/{self.selected_factor_id}",
                headers={'Content-Type': 'application/json'},
                data=json.dumps(hint)
            )
            if not response.ok:
                raise Exception(response.text or 'Failed to send code.')
        except Exception as e:
            self.error = str(e)
            raise e  # 重新抛出以由调用者处理

    def handle_factor_selected(self):
        selected_factor = self.get_selected_factor()
        if not selected_factor:
            self.error = 'Please select an authentication method.'
            return

        # 对于密码或TOTP，直接进入下一步
        if selected_factor['type'] == 0 or selected_factor['type'] == 2:
            self.stage = 'enter-code'
            return

        # 对于邮箱，先发送验证码
        if selected_factor['type'] == 1:
            self.error = None
            try:
                self.request_verification_code(selected_factor['contact'])
                self.stage = 'enter-code'
            except Exception:
                # 错误已经在request_verification_code中设置
                pass

    def get_selected_factor(self):
        if not self.selected_factor_id:
            return None
        return next((factor for factor in self.factors if factor['id'] == self.selected_factor_id), None)

    def handle_verify_factor(self):
        if not self.selected_factor_id or not self.password:
            self.error = 'Please enter your password/code.'
            return

        self.error = None
        try:
            response = requests.patch(
                f"{self.base_url}/api/auth/challenge/{self.challenge['id']}",
                headers={'Content-Type': 'application/json'},
                data=json.dumps({
                    'factor_id': self.selected_factor_id,
                    'password': self.password,
                })
            )
            if not response.ok:
                raise Exception(response.text or 'Verification failed.')

            self.challenge = response.json()
            self.password = ''
            if self.challenge['step_remain'] == 0:
                self.stage = 'token-exchange'
                self.exchange_token()
            else:
                self.get_factors()
                self.stage = 'select-factor'  # 多因素认证步骤
        except Exception as e:
            self.error = str(e)

    def exchange_token(self):
        self.error = None
        try:
            response = requests.post(
                f"{self.base_url}/api/auth/token",
                headers={'Content-Type': 'application/json'},
                data=json.dumps({
                    'grant_type': 'authorization_code',
                    'code': self.challenge['id'],
                })
            )
            if not response.ok:
                raise Exception(response.text or 'Token exchange failed.')

            token_info = response.json()
            token = token_info['token']
            self.user_store.fetchUser()
            redirect_uri = 'redirect_uri_from_query'  # 这里需要根据实际情况获取
            if redirect_uri:
                print(f"Redirecting to: {redirect_uri}")
            else:
                print("Navigating to home page.")
        except Exception as e:
            self.error = str(e)
            self.stage = 'select-factor'  # 如果令牌交换失败，返回选择认证因素阶段

    def get_factor_name(self, factor_type):
        factor_names = {
            0: 'Password',
            1: 'Email',
            2: 'Authenticator App',
        }
        return factor_names.get(factor_type, 'Unknown Factor')

    def login(self, account_identifier, selected_factor_id, password):
        """
        整合登录流程的函数

        :param account_identifier: 用户的账户标识符（邮箱或用户名）
        :param selected_factor_id: 用户选择的认证因素ID
        :param password: 用户输入的密码或验证码
        """
        self.account_identifier = account_identifier
        self.selected_factor_id = selected_factor_id
        self.password = password

        # 生成设备指纹
        self.generate_device_id()

        # 查找账户并获取挑战信息
        self.handle_find_account()
        if self.error:
            print(f"Error in find account: {self.error}")
            return

        # 获取可用的认证因素
        if self.stage == 'select-factor':
            self.get_factors()
            if self.error:
                print(f"Error in get factors: {self.error}")
                return

        # 用户选择认证因素
        if self.stage == 'select-factor':
            self.handle_factor_selected()
            if self.error:
                print(f"Error in handle factor selected: {self.error}")
                return

        # 用户输入验证码或密码
        if self.stage == 'enter-code':
            self.handle_verify_factor()
            if self.error:
                print(f"Error in verify factor: {self.error}")
                return

        # 交换令牌以完成登录
        if self.stage == 'token-exchange':
            self.exchange_token()
            if self.error:
                print(f"Error in exchange token: {self.error}")
                return

# 示例调用
if __name__ == "__main__":
    auth_client = AuthClient(base_url='https://solian.app')
    account_identifier = 'nanci'
    selected_factor_id = 0  # 用户需要选择一个因素
    password = 'test'  # 用户输入的密码或验证码

    # 模拟用户选择第一个可用的因素
    auth_client.login(account_identifier, selected_factor_id, password)
    if auth_client.stage == 'select-factor':
        if auth_client.factors:
            selected_factor_id = auth_client.factors[0]['id']
            auth_client.login(account_identifier, selected_factor_id, password)

    # 用户输入密码或验证码
    if auth_client.stage == 'enter-code':
        password = 'verification_code_or_password'
        auth_client.login(account_identifier, selected_factor_id, password)

    # 如果令牌交换成功
    if auth_client.stage == 'token-exchange':
        print("Login successful!")
    else:
        print("Login failed.")
