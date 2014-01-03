import time
import hashlib
import json
import sys

# External imports
import requests
from Crypto.Cipher import AES


PATTERN = "0001110111101110001111010101111011010001001110011000110001000110"
SECRET = "iEk21fuwZApXlz93750dmW22pw389dPwOk"
STATIC_TOKEN = "m198sOkJEn37DjqZ32lpRu76xmw288xSQ9"

ENCRYPT_KEY_2 = "M02cnQ51Ji97vwT4"
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
unpad = lambda s : s[0:-ord(s[-1])]


def getTime():
    return int(round(time.time() * 1000))


def createStaticToken(time=None):
    time_str = getTime() if time is None else time
    return createToken(STATIC_TOKEN, time_str)


def createToken(server_token, time_str):
    unhashed_1 = SECRET + server_token
    unhashed_2 = str(time_str) + SECRET

    hash_1 = hashlib.sha256(unhashed_1).hexdigest()
    hash_2 = hashlib.sha256(unhashed_2).hexdigest()

    final_hash = ""

    for i in range(0, len(hash_1)):
        final_hash += hash_2[i] if PATTERN[i] is "1" else hash_1[i]

    return final_hash


def login(username, password):
    timestamp = getTime()
    params = {'timestamp': timestamp, 'req_token': createStaticToken(time=timestamp), 'username': username, 'password': password}
    r = requests.post("https://feelinsonice.appspot.com/ph/login", data=params)  #, proxies=proxies)

    return r.text


def sync(auth_token, username):
    timestamp = getTime()
    params = {'timestamp': timestamp, 'req_token': createToken(auth_token, timestamp), 'json': '{}', 'username': username}
    r = requests.post("https://feelinsonice.appspot.com/ph/sync", data=params)  #, proxies=proxies)

    return r.text


def save_img(raw, img_id, target=None):
    if target is None:
        target = img_id
    test_file = open(str(target) + ".jpg", "w")
    test_file.write(raw)
    test_file.close()

    return True


def save_vid(raw, vid_id, target=None):
    if target is None:
        target = img_id
    test_file = open(str(target) + ".mp4", "w")
    test_file.write(raw)
    test_file.close()

    return True


def download_and_decrypt_url(img_url, item_id, is_vid, target=None):
    img_string = requests.get(img_url).content
    cipher = AES.new(ENCRYPT_KEY_2)

    raw = cipher.decrypt(pad(img_string))
    if is_vid:
        return save_vid(raw, item_id, target)
    return save_img(raw, item_id, target)


def get_url(img_id, username, auth_token):
    time = str(getTime())
    url = "https://feelinsonice.appspot.com/ph/blob?id={}".format(img_id)
    url += "&username=" + username + "&timestamp=" + time + "&req_token=" + createToken(auth_token, time)
    return url


def get_image(img_id, username, auth_token, target=None):
    url = get_url(img_id, username, auth_token)
    return download_and_decrypt_url(url, img_id, False, target)


def get_video(vid_id, username, auth_token, target=None):
    url = get_url(vid_id, username, auth_token)
    return download_and_decrypt_url(url, vid_id, True, target)


def time_filename(timestamp):
    return datetime.datetime.fromtimestamp(timestamp).strftime("%Y%m%dT%H%M%S")

def download_unread(username, password):
    auth_token = json.loads(login(username, password))['auth_token']

    res = json.loads(sync(auth_token, username))

    for snap in res['snaps']:
        if 'm' not in snap or 'rp' in snap:
            # Either the format has changed, or this was a sent snap.
            continue
        timestamp = time.localtime(snap['sts'] / 1000)
        sender = snap['sn']
        message = "getting {0} from " + sender + " at " + time.asctime(timestamp) + ": " + snap['id']
        target = time.strftime("%Y%m%dT%H%M%S", timestamp) + "_" + sender

        if snap['m'] == 0 and snap['st'] == 1:
            print message.format("pic")
            get_image(snap['id'], username, auth_token, target)
        elif snap['m'] == 1 and snap['st'] == 1:
            print message.format("video")
            get_video(snap['id'], username, auth_token, target)


if __name__ == "__main__":
    if len(sys.argv) not in [2, 3]:
        print "Usage: python snapchat.py username [password]"
    else:
        try:
            password = sys.argv[2]
        except IndexError:
            import getpass
            password = getpass.getpass()
        download_unread(sys.argv[1], password)
