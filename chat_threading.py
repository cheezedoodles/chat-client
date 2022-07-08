import websockets
import asyncio
import threading
import time
import json
import sys
import msvcrt

commands = ['/exit', '/chat']

class Chat(threading.Thread):

    stdout_lock = threading.Lock()

    async def send(self, message):
        await self.ws.send(message)
        #await self.receiver()
            

    async def receiver(self):
        async with websockets.connect(
            'ws://127.0.0.1:8000/ws/chat/1/',
            origin='http://127.0.0.1:8000'
        ) as websocket:
            self.ws = websocket
            while True:
                self.new_msg = await self.ws.recv()
                print(json.loads(self.new_msg)['message'])
                #await self.send(json.dumps({'message': str((input('Message:')))}))

    def send_wrapper(self, msg):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        loop.run_until_complete(self.send(msg))
        loop.close() 

    def receiver_wrapper(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        #self.ws = None
        loop.run_until_complete(self.receiver())
        loop.close()

    def run(self):
        self.receiver_wrapper()


class Menu(threading.Thread):

    stdout_lock = threading.Lock()

    def parse_commands(self, command):
        if command.startswith('/chat'):
            self.socket = Chat()
            self.socket.daemon = True
            #if not self.socket.is_alive():
            self.socket.start()
            #self.socket.join()
            
            self.run()

    # def run(self):
    #     while True:
    #         s = input()
    #         if s == '/exit':
    #             sys.exit()
    #         elif s not in commands:
    #             msg = json.dumps({'message': str(s)})
    #             self.socket.send_wrapper(msg)
    #         else:
    #             self.parse_commands(s)

    def get_input(self):
        s = ''
        ch = ''
        while True:
            if msvcrt.kbhit():
                ch = msvcrt.getwch()
                if ch == '\r':
                    break
                else:
                    s += ch
        return s

    def run(self):
        while True:
            s = self.get_input()
            if s == '/exit':
                sys.exit()
            elif s not in commands:
                msg = json.dumps({'message': str(s)})
                self.socket.send_wrapper(msg)
            else:
                self.parse_commands(s)

if __name__ == "__main__":
    t1 = Menu()
    t1.start()