#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2013-2015 clowwindy
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# from ssloop
# https://github.com/clowwindy/ssloop

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import time
import socket
import select
import errno
import logging
from collections import defaultdict

from shadowsocks import shell


__all__ = ['EventLoop', 'POLL_NULL', 'POLL_IN', 'POLL_OUT', 'POLL_ERR',
           'POLL_HUP', 'POLL_NVAL', 'EVENT_NAMES']

POLL_NULL = 0x00
POLL_IN = 0x01
POLL_OUT = 0x04
POLL_ERR = 0x08
POLL_HUP = 0x10
POLL_NVAL = 0x20


EVENT_NAMES = {
    POLL_NULL: 'POLL_NULL',
    POLL_IN: 'POLL_IN',
    POLL_OUT: 'POLL_OUT',
    POLL_ERR: 'POLL_ERR',
    POLL_HUP: 'POLL_HUP',
    POLL_NVAL: 'POLL_NVAL',
}

# we check timeouts every TIMEOUT_PRECISION seconds
TIMEOUT_PRECISION = 10

#kqueue=select.kqueue()返回一个内核的queue object
#该kqueue拥有以下方法:
#1.kqueue.close() Close the control file descriptor of the kqueue object. 关闭kqueue实例的控制文件描述符
#2.kqueue.closed  True if the kqueue object is close. kqueue实例是否关闭
#3.kqueue.fileno() Return the file descriptor number of the control fd.返回返回控制文件的数字格式的文件描述符
#4.kqueue.fromfd(fd) Create a kqueue object from a given file descriptor. 从一个给定的文件描述符创建一个kqueue实例对象
#5.kqueue.control(changelist, max_events[, timeout=None]) -->eventlist. 返回一个事件列表（kevent事件）。用于开始监听并返回监听到的kevent
#  ·changelist must be an iterable of kevent object or None
#  ·max_events must be 0 or a positive integer
#  ·timeout in seconds (floats possible)
#select.kevent(ident, filter=KQ_FILTER_READ, flags=KQ_EV_ADD, fflags=0, data=0, udata=0)Returns a kernel event object.返回一个（用于监听）内核event对象
#kevent事件内容:{kevent.ident:value, kevent.filter:value, kevent.flags:value, kevent.fflags:value, kevent.data:value, kevent.udata:value}
#kevent.ident: Value used to identify the event. The interpretation depends on the filter but it’s usually the file descriptor. In the constructor ident can either be an int or an object with a fileno() method. kevent stores the integer internally.它的值用来标识一个事件。它的解释依赖于filter，但通常代表文件描述符。
#kevent.filter: Name of the kernel filter. 内核过滤器的名称
#filter常量:
#Constant           Meaning
#KQ_FILTER_READ     Takes a descriptor and returns whenever there is data available to read
#KQ_FILTER_WRITE    Takes a descriptor and returns whenever there is data available to write
#KQ_FILTER_AIO      AIO requests
#KQ_FILTER_VNODE    Returns when one or more of the requested events watched in fflag occurs
#KQ_FILTER_PROC     Watch for events on a process id
#KQ_FILTER_NETDEV   Watch for events on a network device [not available on Mac OS X]
#KQ_FILTER_SIGNAL   Returns whenever the watched signal is delivered to the process
#KQ_FILTER_TIMER    Establishes an arbitrary timer
#kevent.flags: Filter action. 过滤器对应的执行动作
#flags常量包括:
#Constant       Meaning
#KQ_EV_ADD      Adds or modifies an event
#KQ_EV_DELETE   Removes an event from the queue
#KQ_EV_ENABLE   Permitscontrol() to returns the event
#KQ_EV_DISABLE  Disablesevent
#KQ_EV_ONESHOT  Removes event after first occurrence
#KQ_EV_CLEAR    Reset the state after an event is retrieved
#KQ_EV_SYSFLAGS internal event
#KQ_EV_FLAG1    internal event
#KQ_EV_EOF      Filter specific EOF condition
#KQ_EV_ERROR    See return values
#kevent.data: Filter specific data.
#kevent.udata: User defined value.

class KqueueLoop(object):

    MAX_EVENTS = 1024

    def __init__(self):
        self._kqueue = select.kqueue()
        self._fds = {}

    def _control(self, fd, mode, flags):
        events = []
        if mode & POLL_IN:
            #生成一个文件描述符fd的读操作事件，并添加到events列表中，用于后续监听
            events.append(select.kevent(fd, select.KQ_FILTER_READ, flags))
        if mode & POLL_OUT:
            #生成一个文件描述符fd的写操作事件，并添加到events列表中，用于后续监听
            events.append(select.kevent(fd, select.KQ_FILTER_WRITE, flags))
        for e in events:
            self._kqueue.control([e], 0)

    def poll(self, timeout):
        if timeout < 0:
            timeout = None  # kqueue behaviour
        #开始监听kqueue，并返回一个kevent.{kevent.ident:value, kevent.filter:value, kevent.flags:value, kevent.fflags:value, kevent.data:value, kevent.udata:value}
        events = self._kqueue.control(None, KqueueLoop.MAX_EVENTS, timeout)
        results = defaultdict(lambda: POLL_NULL)
        for e in events:
            fd = e.ident
            if e.filter == select.KQ_FILTER_READ:
                results[fd] |= POLL_IN
            elif e.filter == select.KQ_FILTER_WRITE:
                results[fd] |= POLL_OUT
        return results.items()

    def register(self, fd, mode):
        self._fds[fd] = mode
        self._control(fd, mode, select.KQ_EV_ADD)

    def unregister(self, fd):
        self._control(fd, self._fds[fd], select.KQ_EV_DELETE)
        del self._fds[fd]

    def modify(self, fd, mode):
        self.unregister(fd)
        self.register(fd, mode)

    def close(self):
        self._kqueue.close()

#select.select()进程指定内核监听哪些文件描述符的事件(最多1024个文件描述符fd),当没有文件描述符事件发生时,进程被阻塞;当一个或多个文件描述符事件发生时,进程被唤醒
#当调用select()时:
#1.上下文切换为内核态
#2.将fd从用户空间复制到内核空间
#3.内核遍历所有fd,查看其对应事件是否发生
#4.如果没有发生,将进程阻塞,当设备驱动产生终端或者timeout时间后，将进程唤醒，再次进行遍历
#5.返回遍历后的fd
#6.将fd从内核空间复制到用户空间
#fd_r_list, fd_w_list, fd_e_list = select.select(rlist, wlist, xlist, [timeout])
#参数： 可接受四个参数（前三个必须）
#rlist: wait until ready for reading，即我们需要内核监听的读文件描述符列表，当读事件触发时，返回对应的文件描述符列表
#wlist: wait until ready for writing，即我们需要内核监听的写文件描述符列表，当写事件触发时，返回对应的文件描述符列表
#xlist: wait for an “exceptional condition”
#timeout: 超时时间
#返回值：三个列表
#select方法用来监视文件描述符(当文件描述符条件不满足时，select会阻塞)，当某个文件描述符状态改变后，会返回三个列表
#1、当参数1 序列中的fd满足“可读”条件时，则获取发生变化的fd并添加到fd_r_list中
#2、当参数2 序列中含有fd时，则将该序列中所有的fd添加到 fd_w_list中
#3、当参数3 序列中的fd发生错误时，则将该发生错误的fd添加到 fd_e_list中
#4、当超时时间为空，则select会一直阻塞，直到监听的句柄发生变化
#   当超时时间 ＝ n(正整数)时，那么如果监听的句柄均无任何变化，则select会阻塞n秒，之后返回三个空列表，如果监听的句柄有变化，则直接执行。
class SelectLoop(object):

    def __init__(self):
        self._r_list = set()    #set()创建空的集合.集合中的元素可以保证非重复.使用set.add(e),set.update([]),set.remove(e)来实现增删操作
        self._w_list = set()
        self._x_list = set()

    def poll(self, timeout):
        r, w, x = select.select(self._r_list, self._w_list, self._x_list,
                                timeout)
        #dict = connections.defaultdict()返回一个带缺省值的dict. dict[item] = value,当item不存在时会创建对应条目并赋值为value
        results = defaultdict(lambda: POLL_NULL)
        for p in [(r, POLL_IN), (w, POLL_OUT), (x, POLL_ERR)]:
            for fd in p[0]:
                results[fd] |= p[1]
        #dict.items()返回可遍历的(键, 值) 元组数组。
        #eg:  dict       = {'a': 3, 'b': 1, 'c': 1, 'd': 2, 'e': 2}
        #     dict.items = [('a', 3), ('b', 1), ('c', 1), ('d', 2), ('e', 2)]
        return results.items()

    def register(self, fd, mode):
        if mode & POLL_IN:
            self._r_list.add(fd)
        if mode & POLL_OUT:
            self._w_list.add(fd)
        if mode & POLL_ERR:
            self._x_list.add(fd)

    def unregister(self, fd):
        if fd in self._r_list:
            self._r_list.remove(fd)
        if fd in self._w_list:
            self._w_list.remove(fd)
        if fd in self._x_list:
            self._x_list.remove(fd)

    def modify(self, fd, mode):
        self.unregister(fd)
        self.register(fd, mode)

    def close(self):
        pass

#select.epoll()方法
#1  epoll的解决方案在epoll_ctl函数中。每次注册新的事件到epoll句柄中时，会把所有的fd拷贝进内核，而不是在epoll_wait的时候重复拷贝。
#   epoll保证了每个fd在整个过程中只会拷贝一次。
#2  epoll会在epoll_ctl时把指定的fd遍历一遍（这一遍必不可少）并为每个fd指定一个回调函数，当设备就绪，唤醒等待队列上的等待者时，就会调
#   用这个回调函数，而这个回调函数会把就绪的fd加入一个就绪链表。epoll_wait的工作实际上就是在这个就绪链表中查看有没有就绪的fd
#3  epoll对文件描述符没有额外限制
#select.epoll(sizehint=-1, flags=0) 创建epoll对象
#1.epoll.close()   Close the control file descriptor of the epoll object.关闭epoll对象的文件描述符
#2.epoll.closed    True if the epoll object is closed.检测epoll对象是否关闭
#3.epoll.fileno()  Return the file descriptor number of the control fd.返回epoll对象的文件描述符
#4.epoll.fromfd(fd)Create an epoll object from a given file descriptor.根据指定的fd创建epoll对象
#5.epoll.register(fd[, eventmask]) Register a fd descriptor with the epoll object.向epoll对象中注册fd和对应的事件
#6.epoll.modify(fd, eventmask)  Modify a registered file descriptor.修改fd的事件
#7.epoll.unregister(fd) Remove a registered file descriptor from the epoll object.取消注册
#8.epoll.poll(timeout=-1, maxevents=-1)Wait for events. timeout in seconds (float)阻塞，直到注册的fd事件发生,会返回一个dict，格式为：{(fd1,event1),(fd2,event2),……(fdn,eventn)}
#EPOLL 事件
#EPOLLIN    Available for read 可读   状态符为1
#EPOLLOUT    Available for write 可写  状态符为4
#EPOLLPRI    Urgent data for read
#EPOLLERR    Error condition happened on the assoc. fd 发生错误 状态符为8
#EPOLLHUP    Hang up happened on the assoc. fd 挂起状态
#EPOLLET    Set Edge Trigger behavior, the default is Level Trigger behavior 默认为水平触发，设置该事件后则边缘触发
#EPOLLONESHOT    Set one-shot behavior. After one event is pulled out, the fd is internally disabled
#EPOLLRDNORM    Equivalent to EPOLLIN
#EPOLLRDBAND    Priority data band can be read.
#EPOLLWRNORM    Equivalent to EPOLLOUT
#EPOLLWRBAND    Priority data may be written.
#EPOLLMSG    Ignored.

class EventLoop(object):
    def __init__(self):
        if hasattr(select, 'epoll'):
            self._impl = select.epoll()
            model = 'epoll'
        elif hasattr(select, 'kqueue'):
            self._impl = KqueueLoop()
            model = 'kqueue'
        elif hasattr(select, 'select'):
            self._impl = SelectLoop()
            model = 'select'
        else:
            raise Exception('can not find any available functions in select '
                            'package')
        self._fdmap = {}  # (f, handler)
        self._last_time = time.time()
        self._periodic_callbacks = []
        self._stopping = False
        logging.debug('using event model: %s', model)

    def poll(self, timeout=None):
        events = self._impl.poll(timeout)
        return [(self._fdmap[fd][0], fd, event) for fd, event in events]

    def add(self, f, mode, handler):
        fd = f.fileno()
        self._fdmap[fd] = (f, handler)
        self._impl.register(fd, mode)

    def remove(self, f):
        fd = f.fileno()
        del self._fdmap[fd]
        self._impl.unregister(fd)

    def add_periodic(self, callback):
        self._periodic_callbacks.append(callback)

    def remove_periodic(self, callback):
        self._periodic_callbacks.remove(callback)

    def modify(self, f, mode):
        fd = f.fileno()
        self._impl.modify(fd, mode)

    def stop(self):
        self._stopping = True

    def run(self):
        events = []
        while not self._stopping:
            asap = False
            try:
                events = self.poll(TIMEOUT_PRECISION)
            except (OSError, IOError) as e:
                if errno_from_exception(e) in (errno.EPIPE, errno.EINTR):
                    # EPIPE: Happens when the client closes the connection
                    # EINTR: Happens when received a signal
                    # handles them as soon as possible
                    asap = True
                    logging.debug('poll:%s', e)
                else:
                    logging.error('poll:%s', e)
                    import traceback
                    traceback.print_exc()
                    continue

            for sock, fd, event in events:
                handler = self._fdmap.get(fd, None)
                if handler is not None:
                    handler = handler[1]
                    try:
                        handler.handle_event(sock, fd, event)
                    except (OSError, IOError) as e:
                        shell.print_exception(e)
            now = time.time()
            if asap or now - self._last_time >= TIMEOUT_PRECISION:
                for callback in self._periodic_callbacks:
                    callback()
                self._last_time = now

    def __del__(self):
        self._impl.close()


# from tornado
def errno_from_exception(e):
    """Provides the errno from an Exception object.

    There are cases that the errno attribute was not set so we pull
    the errno out of the args but if someone instatiates an Exception
    without any args you will get a tuple error. So this function
    abstracts all that behavior to give you a safe way to get the
    errno.
    """

    if hasattr(e, 'errno'):
        return e.errno
    elif e.args:
        return e.args[0]
    else:
        return None


# from tornado
def get_sock_error(sock):
    error_number = sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
    return socket.error(error_number, os.strerror(error_number))
