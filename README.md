# chat-client

Chat-client is a graphical user interface made with PyQt5 that is used as a frontend for the vernamcipher-chatapp.

## Installation

For now you can clone from the staging branch, but it will be merged with master soon.

```bash
git clone --branch staging https://github.com/cheezedoodles/chat-client.git
```
You'll also need to install some python modules:
```bash
pip install -r requirements.txt
```

## Usage

Don't forget to start a Redis server:
```bash
docker run -p 6379:6379 -d redis:5
```
and a django server cloned from the vernamcipher-chatapp repository:
```bash
python manage.py runserver
```
Before you run client.py for the first time you'll need to generate a key file by running the following command:
```bash
python key_generator.py
```
And then run:
```bash
python client.py
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License
[MIT](https://choosealicense.com/licenses/mit/)