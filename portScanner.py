import queue
import socket
import threading
from subprocess import PIPE, Popen
from random import randint
from time import sleep


RETRY_TIME = 2
RETRY_WAIT_TIME = 0.2
LISTEN_PORT = 12321
THREAD_NUM = 8

PORT_FILTERED = 1
PORT_OPEN = 2
PORT_CLOSE = 3


def getHostIp():
    '''
    获得内网 Ip.
    '''
    try:
        sck = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sck.connect(('8.8.8.8', 80))
        ip = sck.getsockname()[0]
    finally:
        sck.close()
    return ip


def makeByteArray(num, byteSize):
    '''
    将数字转化为 bytearray.
    '''
    result = bytearray()
    num = bin(num)[2:].zfill(byteSize * 8)  #补零
    for i in range(0, len(num), 8):
        result.append(int(num[i:i + 8], 2))  #按字节分割
    return result


def transIp2Bytes(addr):
    '''
    将 Ip 转换为 bytearray.
    '''
    addr = addr.split(".")
    result = bytearray()
    for num in addr:
        result.extend(makeByteArray(int(num), 1))
    return result


def calcCheckSum(srcIp, targetIp, tcpHead):
    ''''
    计算效验和.
    '''
    psdHeader = bytearray()
    psdHeader.extend(srcIp)  #来源 Ip
    psdHeader.extend(targetIp)  #目标 Ip
    psdHeader.extend(makeByteArray(0, 1))  #补零
    psdHeader.extend(makeByteArray(socket.IPPROTO_TCP, 1))  #TCP 协议号
    psdHeader.extend(makeByteArray(len(tcpHead), 2))  #TCP 长度
    psdHeader.extend(tcpHead)

    checkSum = 0
    for i in range(0, len(psdHeader), 2):
        checkSum += ((psdHeader[i] << 8) + psdHeader[i + 1])
        checkSum = (checkSum >> 16) + (checkSum & 0xffff)

    checkSum = ~checkSum & 0xffff
    return checkSum


def makeTCPSyn(srcIp, targetIp, srcPort, targetPort):
    '''
    制作 syn 包.
    '''
    tcpPayload = bytearray()
    tcpPayload.extend(makeByteArray(srcPort, 2))  #来源端口
    tcpPayload.extend(makeByteArray(targetPort, 2))  #目标端口
    tcpPayload.extend(makeByteArray(randint(0x10000000, 0xAAAAAAAA), 4))  #SYN 序列号, 随机生成一个
    tcpPayload.extend(makeByteArray(0, 4))  #ACK 序列号
    tcpPayload.extend(makeByteArray(0b0110000000000010, 2))  #数据开始的偏移量、保留字段以及标识符 我们只需要填充 SYN 的标准位为 1 即可
    tcpPayload.extend(makeByteArray(randint(300, 1460), 2))  #窗口大小, 大小随意
    tcpPayload.extend(makeByteArray(0, 2))  #check sum, 先用 0 填充
    tcpPayload.extend(makeByteArray(0, 2))  #紧急指针
    tcpPayload.extend(makeByteArray(2, 1))  #这个以及下面的为 tcp options
    tcpPayload.extend(makeByteArray(4, 1))
    tcpPayload.extend(makeByteArray(1460, 2))

    checkSum = makeByteArray(calcCheckSum(srcIp, targetIp, tcpPayload), 2)
    tcpPayload[16] = checkSum[0]  #将 checksum 替换为计算好的值
    tcpPayload[17] = checkSum[1]
    return tcpPayload


def analyzeRes(response):
    '''
    获取回应的端口状态和端口号.
    '''
    port = (response[20] << 8) + response[21]
    if (response[22] << 8) + response[23] != LISTEN_PORT: #检查是否是发向自己这个端口的
        return

    if (response[33] >> 2) & 1:  #RST 位
        return (port, PORT_CLOSE)
    elif (response[33] >> 4) & 1:  #SYN 位
        return (port, PORT_OPEN)
    raise Exception("Invaild head.")


class slaver():
    inputQueue: queue.Queue
    outputDict: dict
    localAddr: tuple

    def __init__(self, inputQueue, outputDict, localAddr):
        self.inputQueue = inputQueue
        self.outputDict = outputDict
        self.localAddr = localAddr

    def startWork(self): #队列为空时退出
        sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

        while not self.inputQueue.empty():
            remoteAddr = self.inputQueue.get()
            payload = makeTCPSyn(transIp2Bytes(self.localAddr[0]), transIp2Bytes(remoteAddr[0]), self.localAddr[1], remoteAddr[1])
            retriedTime = 0
            while self.outputDict[remoteAddr[1]] == 1 and retriedTime < RETRY_TIME:
                sck.sendto(payload, remoteAddr)
                retriedTime += 1
                sleep(RETRY_WAIT_TIME)


def startSlaver(inputQueue, outputDict, localAddr):
    slaver(inputQueue, outputDict, localAddr).startWork()


class threadPool():
    '''
    简单实现的线程池.
    '''
    inputQueue: queue.Queue
    outputDict: dict
    threads = list()

    def __init__(self, size, inputQueue, outputDict, localAddr):
        self.inputQueue = inputQueue
        self.outputDict = outputDict
        self.localAddr = localAddr

        for i in range(size):
            thread = threading.Thread(target=startSlaver, args=(inputQueue, outputDict, localAddr))
            thread.setDaemon(True)
            self.threads.append(thread)

    def startPool(self):
        for t in self.threads:
            t.start()

    def join(self):
        for thread in self.threads:
            thread.join()


def recvResponse(outputDict, stopSignal):
    '''
    接收回应的包.
    '''
    sck = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    while not stopSignal.is_set():
        res = sck.recv(1024)
        result = analyzeRes(res)
        if result: #analyzeRes 对无效数据包不会返回值
            port, status = result
            outputDict[port] = status


def scanHost(remoteIp, ports):
    '''
    扫描在 `ports` 里的端口.
    '''
    outputDict = dict()
    inputQueue = queue.Queue()
    hostIp = getHostIp()

    for port in ports:
        outputDict[port] = PORT_FILTERED #默认为被过滤
        inputQueue.put((remoteIp, port))

    threads = threadPool(THREAD_NUM, inputQueue, outputDict, (hostIp, LISTEN_PORT))
    threads.startPool()

    signal = threading.Event()
    t = threading.Thread(target=recvResponse, args=(outputDict, signal))
    t.setDaemon(True)
    t.start()

    threads.join()
    signal.set()
    t.join(timeout=RETRY_WAIT_TIME)

    return outputDict


def checkRoot():
    p = Popen("whoami", stdout=PIPE)
    p.wait()

    if p.stdout.read().decode().replace("\n", "") != "root":
        print("Please run in root.")
        exit(0)


def checkPort(port):
    if port < 1 or port > 65535:
        print("Please input vaild ports.")
        exit(0)
    else:
        return port


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Remote host ip.")
    parser.add_argument("ports", help="Remote port range.")
    args = parser.parse_args()
    checkRoot() #检测是否是 root 权限

    remoteIp = socket.gethostbyname(args.host)
    portRange = args.ports
    portRange = portRange.split(",")
    ports = list()
    for r in portRange:
        r = r.strip().split("-")
        if len(r) == 2:
            for i in range(checkPort(int(r[0])), checkPort(int(r[1])) + 1):
                ports.append(i)
        elif len(r) == 1:
            ports.append(checkPort(int(r[0])))
        else:
            print("Please input vaild ports.")

    result = scanHost(remoteIp, ports)

    transDict = {
        PORT_FILTERED: "FILTERED",
        PORT_OPEN: "OPEN",
        PORT_CLOSE: "CLOSED"
    }
    for r in result:
        print(str(r).rjust(5), " ", transDict[result[r]])


