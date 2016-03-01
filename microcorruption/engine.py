import atexit
import os

import requests
import webbrowser

import time
from lxml import html

from requests.packages.urllib3.exceptions import InsecureRequestWarning

from microcorruption.error import MCResponseError

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

hostname = 'https://microcorruption.com%s'


def check_resp(resp):
    if resp.status_code != 200:
        print(resp.content)
        print(resp.status_code)
        raise MCResponseError(resp.text, resp.status_code)

    return resp


session = None


def close_session():
    global session
    if not session:
        return

    print('Cleaning up session')
    url = hostname % '/logout'
    check_resp(session.get(url, verify=False))

    session = None


class Cpu(object):
    cpu_url = hostname % "/cpu/%s"

    MEM_BLOCK_DATA_SIZE = 16
    MEM_BLOCK_STR_SIZE = 32
    MEM_BLOCK_ADDR_SIZE = 4
    MEM_TOP_ADDR = 0x10000

    def __init__(self, engine):
        self.engine = engine
        self.regs = []
        self._memory = {}
        self.insn = None
        self.state = None
        self.isdebug = None

    def is_alive(self):
        mcsession = self.engine.session
        url = self.cpu_url % '/is_alive'
        json_data = {'body': {}}

        resp = check_resp(mcsession.post(url, verify=False, json=json_data))

        return resp.json()

    def set_level(self, level):
        mcsession = self.engine.session
        url = self.cpu_url % '/set_level'
        json_data = {'body': {'level': level}}

        new_level = level.replace(' ', '').lower()
        if new_level not in self.engine._levels:
            if new_level not in self.engine.levels():
                raise Exception('Level "%s" not available' % level)

        resp = check_resp(mcsession.post(url, verify=False, json=json_data))

        if not resp.json().get('success', None) == 'success':
            raise Exception('Failed to set CPU to level "%s"' % level)

    def load(self):
        mcsession = self.engine.session
        url = self.cpu_url % '/load'
        json_data = {'body': {}}

        resp = check_resp(mcsession.post(url, verify=False, json=json_data))
        return resp.json()

    def reset(self, debug=True):
        mcsession = self.engine.session
        if debug:
            url = self.cpu_url % '/reset/debug'
        else:
            url = self.cpu_url % '/reset/nodebug'

        json_data = {'body': {}}
        resp = check_resp(mcsession.post(url, verify=False, json=json_data))

        if not resp.json().get('data', {}).get('success', None):
            raise MCResponseError('Failed to reset (Debug:%s)' % debug)

    def updatememory(self, memlist):

        while len(memlist):
            self._memory[int(memlist[:self.MEM_BLOCK_ADDR_SIZE], 16)] = \
                memlist[self.MEM_BLOCK_ADDR_SIZE:self.MEM_BLOCK_STR_SIZE + self.MEM_BLOCK_ADDR_SIZE]

            memlist = memlist[self.MEM_BLOCK_STR_SIZE + self.MEM_BLOCK_ADDR_SIZE:]

    def memory(self, offset, size):

        chunks = {}

        size = min(size, self.MEM_TOP_ADDR - offset)
        real_size = size * (self.MEM_BLOCK_STR_SIZE / self.MEM_BLOCK_DATA_SIZE)

        while real_size > 0:
            base = offset >> 4 << 4
            mem_block = self._memory.get(base, '0' * self.MEM_BLOCK_STR_SIZE)

            block_offset = (offset - base) * (self.MEM_BLOCK_STR_SIZE / self.MEM_BLOCK_DATA_SIZE)
            block_size = min(self.MEM_BLOCK_STR_SIZE - block_offset, real_size)
            mem_block = mem_block[block_offset:block_offset + block_size]

            chunks[offset] = mem_block

            offset += len(mem_block) / (self.MEM_BLOCK_STR_SIZE / self.MEM_BLOCK_DATA_SIZE)
            real_size -= len(mem_block)

        return chunks

    def snapshot(self):
        mcsession = self.engine.session
        url = self.cpu_url % '/snapshot'
        x = int(time.time() * 1000)

        payload = {'x': x}
        resp = check_resp(mcsession.get(url, verify=False, data=payload)).json()

        self.state = resp['state']
        self.isdebug = resp['isdebug']
        self.regs = resp['regs']
        self.insn = resp['insn']
        self.updatememory(resp['updatememory'])


class Engine(object):
    def __init__(self, username=None, passphrase=None):
        self.username = username
        self.passphrase = passphrase
        self.session = requests.Session()
        self.session.headers.update({'Accept-Encoding': ''})

        self.logged_in = False
        self._cpu = None

        self._levels = {}
        if self.username and self.passphrase:
            self.login()

    @property
    def cpu(self):
        if self._cpu is None:
            self._cpu = Cpu(self)

        return self._cpu

    def login(self):
        global session

        if self.logged_in:
            return

        if not self.username or not self.passphrase:
            raise Exception('Invalid credentials can\'t login')

        self.session.headers.update({'Cache-Control': 'no-cache, private',
                                     'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'})

        url = hostname % '/login'
        resp = check_resp(self.session.get(url, verify=False))
        tree = html.fromstring(resp.text)
        csrf_param = tree.xpath('.//meta[@name="csrf-param"]')[0].attrib['content']
        csrf_value = tree.xpath('.//meta[@name="csrf-token"]')[0].attrib['content']

        payload = {'name': self.username,
                   'password': self.passphrase,
                   csrf_param: csrf_value}

        self.session.headers.update({'Referer': 'https://microcorruption.com/'})

        resp = check_resp(self.session.post(url, data=payload, verify=False))
        tree = html.fromstring(resp.text)
        csrf_value = tree.xpath('.//meta[@name="csrf-token"]')[0].attrib['content']

        self.session.headers.update({'X-CSRF-Token': csrf_value,
                                     'Accept': 'application/json, text/javascript, */*; q=0.01',
                                     'X-Requested-With': 'XMLHttpRequest'
                                     })

        self.session.cookies['guideline_welcome'] = '-1'
        session = self.session

    def logout(self):
        if not self.logged_in:
            return

        close_session()

    def levels(self):
        url = hostname % '/get_levels'
        resp = check_resp(self.session.get(url, verify=False))
        self._levels = {x['name'].replace(' ', '').lower(): x for x in resp.json()['levels']}

        return self._levels

    def whoami(self):
        url = hostname % '/whoami'
        resp = check_resp(self.session.get(url, verify=False))

        return resp.json()

    @property
    def level(self):
        return self.whoami()['level']

    @level.setter
    def level(self, new_level):
        self.cpu.set_level(new_level)
        self.cpu.load()
        self.cpu.reset(debug=True)
        self.cpu.snapshot()


atexit.register(close_session)
