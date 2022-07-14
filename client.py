import sys
import requests
import json
import websockets
import asyncio
import threading
import queue

from PyQt5.QtWidgets import (QMainWindow, QAction, QApplication,
                             QDesktopWidget, QGridLayout, QPushButton, QWidget,
                             QLineEdit, QPlainTextEdit, QLabel,
                             QMessageBox)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot, pyqtSignal, QObject

from vernamcipher import (generate_key, encrypt,
                          decrypt, calculate_offset)


WEBSOCKET_URL = 'ws://127.0.0.1:8000/ws/chat/'

BASE_URL = 'http://127.0.0.1:8000/'

ORIGIN = 'http://127.0.0.1:8000'


class ChatThread(QObject, threading.Thread):

    rcv = pyqtSignal()

    def __init__(self, chat_id):
        self.chat_id = chat_id
        self.ws = None
        self.new_msg = None
        super().__init__()

    async def send(self, message):
        await self.ws.send(message)

    async def receiver(self):
        async with websockets.connect(
            WEBSOCKET_URL + f'{self.chat_id}/',
            origin=ORIGIN
        ) as websocket:
            self.ws = websocket
            while True:
                self.new_msg = await self.ws.recv()
                message_queue.put(json.loads(self.new_msg)['message'])
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


class Menu(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.populateUI()

        self.resize(400, 400)
        self.center()
        self.setWindowTitle('Menu')
        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def populateUI(self):
        self.createMenu()
        self.statusBar()

        loginWidget = MenuLogin()
        self.setCentralWidget(loginWidget)

    def createMenu(self):
        menuBar = self.menuBar()

        fileMenu = menuBar.addMenu('&File')
        fileMenu.addAction(self.createExitAction())

    def createExitAction(self):
        exitAction = QAction(QIcon('exit.png'), '&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(self.close)
        return exitAction


class MenuLogin(QWidget):

    token = None

    def __init__(self):
        super().__init__()
        username_label = QLabel('<font size="4"> username </font>')
        self.username = QLineEdit(self)

        password_label = QLabel('<font size="4"> password </font>')
        self.password = QLineEdit(self)

        self.loginBtn = QPushButton('Login', self)
        self.registerBtn = QPushButton('Register', self)

        self.auth_errors = QLabel('')

        self.loginBtn.clicked.connect(self.login_user)
        self.registerBtn.clicked.connect(self.register_user)

        self.show()

        grid = QGridLayout()

        grid.addWidget(username_label, 0, 0)
        grid.addWidget(self.username, 0, 1)
        grid.addWidget(password_label, 1, 0)
        grid.addWidget(self.password, 1, 1)
        grid.addWidget(self.auth_errors, 2, 1)
        grid.addWidget(self.loginBtn, 2, 0, 8, 2)
        grid.addWidget(self.registerBtn, 3, 0, 8, 2)

        self.setLayout(grid)

    @pyqtSlot()
    def login_user(self):
        self.auth_errors.setText('')
        username = self.username.text()
        password = self.password.text()
        try:
            login_request = requests.post(
                BASE_URL + 'api/login/',
                json={'username': username,
                      'password': password}
            ).json()
            token = login_request['token']
        except KeyError:
            self.auth_errors.setText('Invalid credentials')
            return

        self.availableChatsWindow = AvailableChats(token, username)
        self.availableChatsWindow.show()

    @pyqtSlot()
    def register_user(self):
        self.auth_errors.setText('')

        username = self.username.text()
        password = self.password.text()

        user_existance = requests.get(
            BASE_URL + f'api/users/{username}/'
        ).json()

        if 'detail' in user_existance:
            requests.post(
                BASE_URL + 'api/create/',
                json={'username': username,
                      'password': password}
            ).json()
            msgbox = QMessageBox()
            msgbox.setText('Signed up successfully')
            msgbox.setWindowTitle('Registration')
            msgbox.setStandardButtons(QMessageBox.Ok)
            msgbox.exec_()

        else:
            self.auth_errors.setText('Account already exists')


class AvailableChats(QWidget):

    def __init__(self, token, username):
        super().__init__()
        self.token = token
        self.current_user = username

        self.resize(400, 400)
        self.center()

        self.chats = QPlainTextEdit()
        self.chats.setReadOnly(True)

        self.pickChat = QLineEdit(self)

        self.continueBtn = QPushButton('Continue', self)
        self.createChatBtn = QPushButton('Create chat', self)

        chats = self.get_chats()
        self.ids = []
        self.chats.appendPlainText('Pick the chat number and press continue')

        for _, chat in enumerate(chats):
            self.ids.append(chat['id'])

            self.chats.appendPlainText(
                'Chat ' + str(chat['id']) + ' ' + '--' +
                str(chat['sent_from_id']) + ' ' +
                'with' + ' ' +
                str(chat['sent_to_id'])
            )

        self.continueBtn.clicked.connect(self.pick_chat)
        self.createChatBtn.clicked.connect(self.create_chat)

        self.show()

        grid = QGridLayout()
        grid.setSpacing(3)
        grid.addWidget(self.chats, 0, 0, 1, 3)
        grid.addWidget(self.pickChat, 1, 0, 1, 1)
        grid.addWidget(self.continueBtn, 1, 2)
        grid.addWidget(self.createChatBtn, 2, 2)

        self.setLayout(grid)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    @pyqtSlot()
    def get_chats(self):
        chats = requests.get(
            BASE_URL + 'api/chats/',
            headers={'Authorization': f'Token {self.token}'}
        ).json()['results']
        return chats

    @pyqtSlot()
    def pick_chat(self):
        chat_num = int(self.pickChat.text())
        if chat_num in self.ids:

            self.chatWindow = Chat(chat_num)
            self.chatWindow.show()

            self.hide()
            return
        self.pickChat.setText('Invalid id')

    @pyqtSlot()
    def create_chat(self):
        self.createChat = CreateChat(self.token, self.current_user)
        self.createChat.show()

        self.hide()


class CreateChat(QWidget):

    def __init__(self, token, username):
        super().__init__()
        self.token = token
        self.current_user = username

        self.resize(400, 400)
        self.center()

        self.chats = QPlainTextEdit()
        self.chats.setReadOnly(True)

        self.pickUser = QLineEdit(self)

        self.createChatBtn = QPushButton('Create chat', self)
        self.createChatBtn.clicked.connect(self.create_chat)

        self.users = self.show_users()
        self.show()

        grid = QGridLayout()
        grid.setSpacing(3)
        grid.addWidget(self.chats, 0, 0, 1, 3)
        grid.addWidget(self.pickUser, 1, 0, 1, 1)
        grid.addWidget(self.createChatBtn, 1, 2)

        self.setLayout(grid)

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def show_users(self):
        users_to_check = []

        users = requests.get(
            BASE_URL + 'api/users/',
            headers={'Authorization': f'Token {self.token}'}
            ).json()['results']

        self.chats.setPlainText('')
        for _, user in enumerate(users):
            self.chats.appendPlainText(
                user['username']
            )
            users_to_check.append(user['username'])

        return users_to_check

    @pyqtSlot()
    def create_chat(self):
        username = self.pickUser.text()

        if username in self.users:
            requests.post(
                BASE_URL + 'api/chats/',
                json={'sent_from_id': self.current_user,
                      'sent_to_id': username},
                headers={'Authorization': f'Token {self.token}'}
                )
            self.availableChats = AvailableChats(self.token, self.current_user)

            self.hide()
            return
        else:
            self.pickUser.setText("This user doesn't exist")


class Chat(QMainWindow):

    def __init__(self, chat_num):
        super().__init__()
        self.chat_num = chat_num
        self.populateUI()

        self.resize(400, 400)
        self.center()
        self.setWindowTitle('Chat')
        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def populateUI(self):
        self.createMenu()
        self.statusBar()

        centralWidget = CentralWidget(self.chat_num)
        self.setCentralWidget(centralWidget)

    def createMenu(self):
        menuBar = self.menuBar()

        fileMenu = menuBar.addMenu('&File')
        fileMenu.addAction(self.createExitAction())

    def createExitAction(self):
        exitAction = QAction(QIcon('exit.png'), '&Exit', self)
        exitAction.setShortcut('Ctrl+Q')
        exitAction.setStatusTip('Exit application')
        exitAction.triggered.connect(self.close)
        return exitAction


class CentralWidget(QWidget):

    def __init__(self, chat_num):
        super().__init__()
        self.chat_num = chat_num

        self.textbox = QPlainTextEdit()
        self.textbox.setReadOnly(True)

        self.chat = QLineEdit(self)
        self.sendBtn = QPushButton('Send', self)

        self.messages = ChatThread(self.chat_num)
        self.messages.daemon = True
        self.messages.start()

        self.show()

        self.get_chat_messages()

        self.sendBtn.clicked.connect(self.send_message)
        self.messages.rcv.connect(self.recieve_message)

        grid = QGridLayout()
        grid.setSpacing(3)
        grid.addWidget(self.textbox, 0, 0, 1, 3)
        grid.addWidget(self.chat, 1, 0, 1, 1)
        grid.addWidget(self.sendBtn, 1, 2)

        self.setLayout(grid)

    @pyqtSlot()
    def recieve_message(self):
        encrypted_message = message_queue.get()
        self.key = generate_key(encrypted_message, self.offset)
        print(self.key, 'a key that is generated to decrypt')
        decrypted_message = decrypt(encrypted_message, self.key)
        print(decrypted_message, 'decrypted message')
        self.offset += len(encrypted_message)
        print(self.offset, 'current offset in recieve messages')
        self.textbox.appendPlainText(decrypted_message)

    @pyqtSlot()
    def get_chat_messages(self):
        chat_history = requests.get(
            BASE_URL + f'api/chat/{self.chat_num}/'
        ).json()

        self.offset = calculate_offset(self.chat_num)

        current_offset = 0
        for _, message in enumerate(chat_history):

            message['message'] = json.loads(message['message'])
            message_len = len(message['message'])

            key = generate_key(message['message'], current_offset)

            current_offset += message_len

            decrypted_message = decrypt(message['message'], key)

            self.textbox.appendPlainText(decrypted_message)

    @pyqtSlot()
    def send_message(self):
        send_value = self.chat.text()
        self.key = generate_key(send_value, self.offset)
        print(self.key, '\n is the key generated')
        encrypted_message = encrypt(send_value, self.key)
        print(encrypted_message, 'is the encrypted sequence of bytes')

        if send_value:
            send_value = json.dumps({'message': encrypted_message})
            self.messages.send_wrapper(send_value)
            self.chat.setText('')


if __name__ == '__main__':
    message_queue = queue.Queue()
    app = QApplication(sys.argv)
    chat = Menu()
    sys.exit(app.exec_())
