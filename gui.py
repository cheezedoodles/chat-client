import sys
import token
import requests
import json
from PyQt5.QtWidgets import (QMainWindow, QAction, QApplication, QDesktopWidget,
                             QDialog, QGridLayout, QPushButton, QWidget,
                             QLineEdit, QPlainTextEdit, QLabel)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import pyqtSlot


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
        self.initUI()
        print('Token is initialized in MenuLogin')

    def initUI(self):
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
        #grid.setSpacing(2)
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
            'http://127.0.0.1:8000/api/login/',
            json={'username': username,
                'password': password}
            ).json()
            token = login_request['token']
            print(f'Token is set to {token}')
        except KeyError: 
            self.auth_errors.setText('Invalid credentials')
            return
        self.availableChatsWindow = AvailableChats(token, username)
        self.availableChatsWindow.show()
        print('Token is given to AvailableChats')

        #self.expiry = login_request['expiry']

    @pyqtSlot()
    def register_user(self):
        self.auth_errors.setText('')
        username = self.username.text()
        password = self.password.text()
        user_existance = requests.get(
            f'http://127.0.0.1:8000/api/users/{username}/'
        ).json()
        print(user_existance)
        if 'detail' in user_existance:
            register_request = requests.post(
            'http://127.0.0.1:8000/api/create/',
            json={'username': username,
                'password': password}
            ).json()
        else:
            self.auth_errors.setText('Account already exists')


class AvailableChats(QWidget):

    def __init__(self, token, username):
        super().__init__()
        self.token = token
        self.current_user = username
        print(f'We get the token - {self.token}')
        self.initUI()

    def initUI(self):
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
        for i in range(len(chats)):
            self.ids.append(chats[i]['id'])
            self.chats.appendPlainText(
                'Chat ' + str(chats[i]['id']) + ' ' + '--' + \
                str(chats[i]['sent_from_id']) + ' ' +\
                'with' + ' ' + \
                str(chats[i]['sent_to_id'])
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
            'http://127.0.0.1:8000/api/chats/',
            headers={'Authorization': f'Token {self.token}'}
        ).json()['results']
        print('Token is being used')
        print(len(chats))
        return chats
    
    @pyqtSlot()
    def pick_chat(self):
        chat_num = int(self.pickChat.text())
        if chat_num in self.ids:
            self.chatWindow = Chat(chat_num)
            print(f'Gave the chatnum to Chat')
            self.chatWindow.show()
            self.hide()
            return
        self.pickChat.setText('Invalid id')

    @pyqtSlot()
    def create_chat(self):
        self.createChat = CreateChat(self.token, self.current_user)
        self.createChat.show()
        self.hide()
        # users = requests.get(
        #     f'http://127.0.0.1:8000/api/users/',
        #     headers={'Authorization': f'Token {self.token}'}
        #     ).json()['results']
        # print(users)
        # self.chats.setPlainText('')
        # for i in range(len(users)):
        #     self.chats.appendPlainText(
        #         users[i]['username']
        #     )


class CreateChat(QWidget):

    def __init__(self, token, username):
        super().__init__()
        self.token = token
        self.current_user = username
        print(f'We get the token - {self.token}')
        print(f'current user in CreateChat - {self.current_user}')
        self.initUI()

    def initUI(self):
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
            f'http://127.0.0.1:8000/api/users/',
            headers={'Authorization': f'Token {self.token}'}
            ).json()['results']
        print(users)
        self.chats.setPlainText('')
        for i in range(len(users)):
            self.chats.appendPlainText(
                users[i]['username']
            )
            users_to_check.append(users[i]['username'])
        return users_to_check

    @pyqtSlot()
    def create_chat(self):
        username = self.pickUser.text()
        if username in self.users:
            new_chat = requests.post(
                'http://127.0.0.1:8000/api/chats/',
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
        print(f'Chatnum in Chat - {self.chat_num}')
        self.initUI()

    def initUI(self):
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
        print(f'Chat num if CentralWidget - {self.chat_num}')
        self.initUI()

    def initUI(self):
        self.textbox = QPlainTextEdit()
        self.textbox.setReadOnly(True)
        self.chat = QLineEdit(self)
        self.sendBtn = QPushButton('Send', self)

        self.sendBtn.clicked.connect(self.send_message)
        self.show()
        self.get_chat_messages()
        grid = QGridLayout()
        grid.setSpacing(3)
        grid.addWidget(self.textbox, 0, 0, 1, 3)
        grid.addWidget(self.chat, 1, 0, 1, 1)
        grid.addWidget(self.sendBtn, 1, 2)

        self.setLayout(grid)
    
    @pyqtSlot()
    def get_chat_messages(self):
        print(f'Got the chatnum - {self.chat_num}')
        messages = requests.get(
            f'http://127.0.0.1:8000/api/chat/{self.chat_num}/'
        ).json()
        for i in range(len(messages)):
            self.textbox.appendPlainText(
                messages[i]['message']
            )

    @pyqtSlot()
    def send_message(self):
        send_value = self.chat.text()
        if send_value:
            self.textbox.appendPlainText(send_value)
            self.chat.setText('')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    chat = Menu()
    sys.exit(app.exec_())