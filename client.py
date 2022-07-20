import sys
import requests
import json
import websockets
import asyncio
import threading
import queue

from PyQt5.QtWidgets import (
    QMainWindow,
    QAction,
    QApplication,
    QDesktopWidget,
    QGridLayout,
    QPushButton,
    QWidget,
    QLineEdit,
    QPlainTextEdit,
    QLabel,
    QMessageBox,
)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, pyqtSignal, QObject

from vernamcipher import generate_key, encrypt, decrypt, calculate_offset


WEBSOCKET_URL = "ws://127.0.0.1:8000/ws/chat/"

BASE_URL = "http://127.0.0.1:8000/"

ORIGIN = "http://127.0.0.1:8000"

class CenteringMixin:

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

class MenuAndExitMixin:

    def createMenu(self):
        menuBar = self.menuBar()

        fileMenu = menuBar.addMenu("&File")
        fileMenu.addAction(self.createExitAction())

    def createExitAction(self):
        exitAction = QAction(QIcon("exit.png"), "&Exit", self)
        exitAction.setShortcut("Ctrl+Q")
        exitAction.setStatusTip("Exit application")
        exitAction.triggered.connect(self.close)
        return exitAction

class ChatThread(QObject, threading.Thread):

    rcv = pyqtSignal()

    def __init__(self, chat_id, token, username):
        self.chat_id = chat_id
        self.ws = None
        self.new_msg = None
        self.token = token
        self.username = username
        super().__init__()

    async def send(self, message):
        await self.ws.send(message)

    async def receiver(self):
        async with websockets.connect(
            WEBSOCKET_URL + f"{self.chat_id}/{self.username}/", origin=ORIGIN,
            extra_headers={"Authorization": f"Token {self.token}"}
        ) as websocket:
            self.ws = websocket
            while True:
                self.new_msg = await self.ws.recv()
                message_queue.put(json.loads(self.new_msg))
                self.rcv.emit()

    def send_wrapper(self, msg):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        loop.run_until_complete(self.send(msg))
        loop.close()

    def receiver_wrapper(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        loop.run_until_complete(self.receiver())
        loop.close()

    def run(self):
        self.receiver_wrapper()


class Menu(CenteringMixin, MenuAndExitMixin, QMainWindow):
    def __init__(self):
        super().__init__()
        self.populateUI()
        self.resize(400, 400)
        self.center()
        self.setWindowTitle("Menu")
        self.show()

    def populateUI(self):
        self.createMenu()
        self.statusBar()

        loginWidget = MenuLogin()
        self.setCentralWidget(loginWidget)


class MenuLogin(QWidget):
    def __init__(self):
        super().__init__()
        self.username_label = QLabel('<font size="4"> username </font>')
        self.username = QLineEdit(self)

        self.token = None

        self.password_label = QLabel('<font size="4"> password </font>')
        self.password = QLineEdit(self)
        self.password.setEchoMode(QLineEdit.Password)

        self.login_button = QPushButton("Login", self)
        self.register_button = QPushButton("Register", self)
        self.auth_errors = QLabel("")

        self.login_button.clicked.connect(self.login_user)
        self.register_button.clicked.connect(self.register_user)

        self.show()

        self.create_grid()

    def create_grid(self):
        grid = QGridLayout()

        grid.addWidget(self.username_label, 0, 0)
        grid.addWidget(self.username, 0, 1)
        grid.addWidget(self.password_label, 1, 0)
        grid.addWidget(self.password, 1, 1)
        grid.addWidget(self.auth_errors, 2, 1)
        grid.addWidget(self.login_button, 2, 0, 8, 2)
        grid.addWidget(self.register_button, 3, 0, 8, 2)

        self.setLayout(grid)

    @pyqtSlot()
    def login_user(self):
        self.auth_errors.setText("")
        username = self.username.text()
        password = self.password.text()
        login_request = requests.post(
                BASE_URL + "api/login/",
                json={"username": username, "password": password},
            ).json()
        try:
            self.token = login_request["token"]
        except KeyError:  # TODO: Не обратывай блоком try нормальное поведение системы
            self.auth_errors.setText("Invalid credentials")
            return

        self.availableChatsWindow = AvailableChats(self.token, username)
        self.availableChatsWindow.show()

    def signup_msgbox(self):
        msgbox = QMessageBox()
        msgbox.setText("Signed up successfully")
        msgbox.setWindowTitle("Registration")
        msgbox.setStandardButtons(QMessageBox.Ok)
        msgbox.exec_()

    @pyqtSlot()
    def register_user(self):
        self.auth_errors.setText("")

        username = self.username.text()
        password = self.password.text()

        user_existance = requests.get(BASE_URL + f"api/users/{username}/").json()

        if "detail" in user_existance:
            requests.post(
                BASE_URL + "api/create/",
                json={"username": username, "password": password},
            ).json()
            self.signup_msgbox()
        else:
            self.auth_errors.setText("Account already exists")


class AvailableChats(CenteringMixin, QWidget):
    def __init__(self, token, username):
        super().__init__()
        self.token = token
        self.current_user = username
        self.chatWindow = None
        self.createChat = None

        self.resize(400, 400)
        self.center()

        self.chats = QPlainTextEdit()
        self.chats.setReadOnly(True)

        self.pickChat = QLineEdit(self)

        self.continue_button = QPushButton("Continue", self)
        self.createchat_button = QPushButton("Create chat", self)

        chats = self.get_chats()
        self.ids = []
        self.chats.appendPlainText("Pick the chat number and press continue")

        for _, chat in enumerate(chats):
            self.ids.append(chat["id"])

            chat_id = str(chat["id"])
            sent_from = str(chat["sent_from_id"])
            sent_to = str(chat["sent_to_id"])

            self.chats.appendPlainText(f"Chat {chat_id} -- {sent_from} with {sent_to}")

        self.continue_button.clicked.connect(self.pick_chat)
        self.createchat_button.clicked.connect(self.create_chat)

        self.show()

        self.create_grid()

    def create_grid(self):
        grid = QGridLayout()

        grid.setSpacing(3)
        grid.addWidget(self.chats, 0, 0, 1, 3)
        grid.addWidget(self.pickChat, 1, 0, 1, 1)
        grid.addWidget(self.continue_button, 1, 2)
        grid.addWidget(self.createchat_button, 2, 2)

        self.setLayout(grid)

    @pyqtSlot()
    def get_chats(self):
        chats = requests.get(
            BASE_URL + "api/chats/", headers={"Authorization": f"Token {self.token}"}
        ).json()["results"]
        return chats

    @pyqtSlot()
    def pick_chat(self):
        chat_num = int(self.pickChat.text())
        if chat_num in self.ids:

            self.chatWindow = Chat(chat_num, self.token, self.current_user)
            self.chatWindow.show()

            self.hide()
            return
        self.pickChat.setText("Invalid id")

    @pyqtSlot()
    def create_chat(self):
        self.createChat = CreateChat(self.token, self.current_user)
        self.createChat.show()

        self.hide()


class CreateChat(CenteringMixin, QWidget):
    def __init__(self, token, username):
        super().__init__()
        self.token = token
        self.current_user = username
        self.availableChats = None

        self.resize(400, 400)
        self.center()

        self.chats = QPlainTextEdit()
        self.chats.setReadOnly(True)

        self.pickUser = QLineEdit(self)

        self.createchat_button = QPushButton("Create chat", self)
        self.createchat_button.clicked.connect(self.create_chat)

        self.users = self.show_users()
        self.show()

        self.create_grid()

    def create_grid(self):
        grid = QGridLayout()
        grid.setSpacing(3)
        grid.addWidget(self.chats, 0, 0, 1, 3)
        grid.addWidget(self.pickUser, 1, 0, 1, 1)
        grid.addWidget(self.createchat_button, 1, 2)

        self.setLayout(grid)

    def show_users(self):
        users_to_check = []

        users = requests.get(
            BASE_URL + "api/users/", headers={"Authorization": f"Token {self.token}"}
        ).json()["results"]

        self.chats.setPlainText("")
        for _, user in enumerate(users):
            self.chats.appendPlainText(user["username"])
            users_to_check.append(user["username"])

        return users_to_check

    @pyqtSlot()
    def create_chat(self):
        username = self.pickUser.text()

        if username in self.users:
            requests.post(
                BASE_URL + "api/chats/",
                json={"sent_from_id": self.current_user, "sent_to_id": username},
                headers={"Authorization": f"Token {self.token}"},
            )
            self.availableChats = AvailableChats(self.token, self.current_user)

            self.hide()
            return
        else:
            self.pickUser.setText("This user doesn't exist")


class Chat(CenteringMixin, MenuAndExitMixin, QMainWindow):
    def __init__(self, chat_num, token, username):
        super().__init__()
        self.chat_num = chat_num
        self.token = token
        self.current_user = username
        self.populateUI()

        self.resize(400, 400)
        self.center()
        self.setWindowTitle("Chat")
        self.show()

    def populateUI(self):
        self.createMenu()
        self.statusBar()

        centralWidget = CentralWidget(self.chat_num, self.token, self.current_user)
        self.setCentralWidget(centralWidget)


class CentralWidget(QWidget):
    def __init__(self, chat_num, token, username):
        super().__init__()
        self.chat_num = chat_num
        self.token = token
        self.current_user = username
        self.key = None
        self.offset = None

        self.textbox = QPlainTextEdit()
        self.textbox.setReadOnly(True)

        self.chat = QLineEdit(self)
        self.send_button = QPushButton("Send", self)

        self.messages = ChatThread(self.chat_num, self.token, self.current_user)
        self.messages.daemon = True
        self.messages.start()

        self.show()

        self.get_chat_messages()

        self.send_button.clicked.connect(self.send_message)
        self.messages.rcv.connect(self.receive_message)

        self.create_grid()

    def create_grid(self):
        grid = QGridLayout()
        grid.setSpacing(3)
        grid.addWidget(self.textbox, 0, 0, 1, 3)
        grid.addWidget(self.chat, 1, 0, 1, 1)
        grid.addWidget(self.send_button, 1, 2)

        self.setLayout(grid)

    @pyqtSlot()
    def receive_message(self):
        item = message_queue.get()
        username = item['username']
        encrypted_message = item['message']


        self.key = generate_key(encrypted_message, self.offset)
        decrypted_message = decrypt(encrypted_message, self.key)

        self.offset += len(encrypted_message)

        self.textbox.appendPlainText(f'{username}: {decrypted_message}')

    @pyqtSlot()
    def get_chat_messages(self):
        chat_history = requests.get(
            BASE_URL + f"api/chat/{self.chat_num}/",
            headers={"Authorization": f"Token {self.token}"},
        ).json()

        self.offset = calculate_offset(self.chat_num, self.token)

        current_offset = 0
        for _, message in enumerate(chat_history):

            user = message['user']

            message["message"] = json.loads(message["message"])
            message_len = len(message["message"])

            key = generate_key(message["message"], current_offset)

            current_offset += message_len

            decrypted_message = decrypt(message["message"], key)

            self.textbox.appendPlainText(f'{user}: {decrypted_message}')

    @pyqtSlot()
    def send_message(self):
        send_value = self.chat.text()
        self.key = generate_key(send_value, self.offset)
        encrypted_message = encrypt(send_value, self.key)

        if send_value:
            send_value = json.dumps({"message": encrypted_message})
            self.messages.send_wrapper(send_value)
            self.chat.setText("")


if __name__ == "__main__":
    message_queue = queue.Queue()  # TODO: Лучше передавать по ссылке в классы
    app = QApplication(sys.argv)
    chat = Menu()
    sys.exit(app.exec_())

# TODO: Общее:
#  1) Лучше QTшные классы вынеси по логике
