from sanic import Sanic
from sanic.response import json
from sanic.request import Request
from sanic_session import Session, InMemorySessionInterface
from jsonpickle import dumps, loads
import asyncio
from time import time
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.date import DateTrigger
from datetime import datetime
from port_scanner import scan_host_port, detect_os_type, ping_hosts, split_ip, split_port, PortStatus, OSType, Host, TOP_1000_PORTS, PORT_NAME_MAP, set_event_loop, ScanStatus
import re
import socket
import os
from sanic_cors import CORS


app = Sanic(__name__)

session_interface = InMemorySessionInterface(samesite="None")  # For debug
Session(app, interface=session_interface)

CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)  # For debug

app_password = "admin"
task_list = []
aps_scheduler: AsyncIOScheduler = None


class Task:
    ports: str
    hosts: str
    skip_ping: bool
    only_ping: bool
    ping_timeout: int
    port_timeout: int
    os_timeout: int
    ping_rate: int
    port_rate: int
    os_rate: int
    start_time: int
    hosts_status: dict = {}
    output: str = ""
    scan_status: str

    def print(self, i):
        self.output += i
        self.output += '\n'

    async def start(self):
        self.scan_status = ScanStatus.Scanning.value

        self.hosts_status = {}
        try:
            hosts = self.hosts
            if re.match(r'([0-9]{1,3}(-[0-9]{1,3})?\.){3}[0-9]{1,3}(-[0-9]{1,3})?', hosts):
                hosts = split_ip(hosts)
                for i in hosts:
                    host = Host()
                    host.hostname = None
                    host.ip_addr = i
                    host.is_online = False
                    host.os_type = OSType.Unknown.value
                    host.port_status = []
                    self.hosts_status[i] = host
            else:
                host = Host()
                host.hostname = hosts
                hosts = [socket.gethostbyname(hosts)]

                host.ip_addr = hosts[0]
                host.is_online = False
                host.os_type = OSType.Unknown.value
                host.port_status = []
                self.hosts_status[hosts[0]] = host
        except Exception as e:
            self.print(f'Failed to resolve "{hosts}"')
            return

        if os.getuid() != 0:
            self.print('You need root to run this program')
            return

        if self.skip_ping and self.only_ping:
            self.print("You can't skip ping and only ping host!")
            return

        if not self.skip_ping:
            self.print("Now check hosts is online by ping scan...")
            hosts = await ping_hosts(hosts, self.ping_timeout, self.ping_rate)
            self.print(f"Ping scan done, have {len(hosts)} hosts online, start port scan...\n")

        for i in hosts:
            self.hosts_status[i].is_online = True

        if not self.only_ping:
            ports = self.ports
            if ports == "":
                ports = TOP_1000_PORTS
            else:
                ports = split_port(ports)

            host_with_open_port = {}
            for host in hosts:
                self.print(f"Now scanning {host}...")
                port_result = await scan_host_port(host, ports, self.port_timeout, self.port_rate)
                port_result = [(i[0], i[1].value) for i in port_result]
                self.hosts_status[host].port_status = port_result
                opened_port = [i[0] for i in port_result if i[1] == PortStatus.STATUS_OPEN.value]
                if len(opened_port) != 0:
                    host_with_open_port[host] = opened_port[0]

            self.print(f"Now scanning os type for these hosts...")
            os_result = await detect_os_type(host_with_open_port, self.os_timeout, self.os_rate)
            for i in os_result:
                self.hosts_status[i].os_type = os_result[i].value

        for k, v in self.hosts_status.items():
            host = self.hosts_status[k]
            if host.is_online:
                self.print(f"\nScan report for {k}")
                self.print("Host is online")

                have_open_port = False
                self.print(f"{('PORT').ljust(10, ' ')} STATE SERVICE")
                for port_num, status in host.port_status:
                    if status == PortStatus.STATUS_OPEN.value:
                        have_open_port = True
                        self.print(f"{(str(port_num) + '/tcp').ljust(10, ' ')} OPEN  {PORT_NAME_MAP[port_num]}")

                self.print('')
                if have_open_port:
                    self.print(f"Possible OS type: {host.os_type}")
                else:
                    self.print("Can't detect OS type, need one open port")

        self.scan_status = ScanStatus.Done.value

    async def dispatch(self):
        if int(self.start_time / 1000) > time():
            self.scan_status = ScanStatus.Waiting.value
            trigger = DateTrigger(run_date=datetime.fromtimestamp(int(self.start_time / 1000)))
            aps_scheduler.add_job(self.start, trigger=trigger)
        else:
            asyncio.create_task(self.start())


def disable_unpicklable_dumps(obj):
    return dumps(obj, unpicklable=False)


class Response:
    @staticmethod
    def success(msg, payload):
        return json({'code': 200, 'msg': msg, 'payload': payload}, dumps=disable_unpicklable_dumps)

    @staticmethod
    def fail(msg, payload):
        return json({'code': 500, 'msg': msg, 'payload': payload}, dumps=disable_unpicklable_dumps)

    @staticmethod
    def invalid(msg, payload):
        return json({'code': 400, 'msg': msg, 'payload': payload}, dumps=disable_unpicklable_dumps)


@app.listener('before_server_start')
async def initialize_server(_, loop):
    global aps_scheduler
    set_event_loop(loop)
    aps_scheduler = AsyncIOScheduler({'event_loop': loop})
    aps_scheduler.start()

    if os.path.exists('dumps.json'):
        global task_list
        f = open('dumps.json')
        task_list = loads(f.read())
        f.close()


@app.listener('after_server_stop')
async def stop_server(_, loop):
    f = open('dumps.json', 'w')
    f.write(dumps(task_list))
    f.close()


@app.route("/api/login", methods=['POST'])
async def login(request: Request):
    password = request.json.get('password', None)
    password = str(password)
    res = None
    if password is not None and password == app_password:
        res = Response.success("登录成功", None)
        request['session']['admin'] = True
    else:
        res = Response.fail("密码错误", None)
    return res


@app.route("/api/status", methods=['GET'])
async def login(request: Request):
    if request['session'].get('admin'):
        return Response.success("", None)
    else:
        return Response.fail("", None)


@app.route("/api/list_task", methods=['GET'])
async def list_task(request):
    if not request['session'].get("admin"):
        return Response.fail("", None)

    return Response.success("", task_list)


@app.route("/api/get_one_task", methods=['GET'])
async def get_one_task(request: Request):
    if not request['session'].get("admin"):
        return Response.fail("", None)

    tid = request.json.get('tid', 0)
    tid = int(tid)
    if tid < len(task_list):
        res = Response.success("", task_list[tid])
    else:
        res = Response.fail("ID 不存在", None)
    return res


@app.route("/api/add_task", methods=['POST'])
async def add_task(request: Request):
    if not request['session'].get("admin"):
        return Response.fail("", None)

    attr = {'ports': str, 'hosts': str, 'skip_ping': bool, 'only_ping': bool, 'ping_timeout': int, 'port_timeout': int,
            'os_timeout': int, 'ping_rate': int, 'port_rate': int, 'os_rate': int, 'start_time': int}
    task = Task()
    req = request.json

    for k, v in attr.items():
        if k in req and isinstance(req[k], v):
            setattr(task, k, req[k])
        else:
            return Response.fail(f"[{k}] 参数错误", None)

    task_list.append(task)
    asyncio.create_task(task.dispatch())
    return Response.success("创建成功", None)

app.run()
