#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright 2014-2015 clowwindy
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

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import sys
import logging
import signal
import time
from shadowsocks import common, shell

# this module is ported from ShadowVPN daemon.c


def daemon_exec(config):
    if 'daemon' in config:
        if os.name != 'posix':
            raise Exception('daemon mode is only supported on Unix')
        command = config['daemon']
        if not command:
            command = 'start'
        pid_file = config['pid-file']
        log_file = config['log-file']
        if command == 'start':
            daemon_start(pid_file, log_file)
        elif command == 'stop':
            daemon_stop(pid_file)
            # always exit after daemon_stop
            sys.exit(0)
        elif command == 'restart':
            daemon_stop(pid_file)
            daemon_start(pid_file, log_file)
        else:
            raise Exception('unsupported daemon command %s' % command)


def write_pid_file(pid_file, pid):
    import fcntl
    import stat

    try:
        fd = os.open(pid_file, os.O_RDWR | os.O_CREAT,
                     stat.S_IRUSR | stat.S_IWUSR)
    except OSError as e:
        shell.print_exception(e)
        return -1

    #int fcntl(int fd, int cmd);
    #int fcntl(int fd, int cmd, long arg);
    #int fcntl(int fd, int cmd, struct flock *lock);
    #fcntl()针对(文件)描述符提供控制。参数fd是被参数cmd操作(如下面的描述)的描述符。针对cmd的值，fcntl能够接受第三个参数int arg。
    #fcntl()的返回值与命令有关。如果出错，所有命令都返回－1，如果成功则返回某个其他值
    #下列三个命令有特定返回值：F_DUPFD , F_GETFD , F_GETFL以及F_GETOWN。
    #                     F_DUPFD   返回新的文件描述符
    #                     F_GETFD   返回相应标志
    #                     F_GETFL , F_GETOWN   返回一个正的进程ID或负的进程组ID
    #fcntl函数有5种功能：
    #1. 复制一个现有的描述符(cmd=F_DUPFD).
    #2. 获得／设置文件描述符标记(cmd=F_GETFD或F_SETFD).
    #3. 获得／设置文件状态标记(cmd=F_GETFL或F_SETFL).
    #4. 获得／设置异步I/O所有权(cmd=F_GETOWN或F_SETOWN).
    #5. 获得／设置记录锁(cmd=F_GETLK , F_SETLK或F_SETLKW).
    #1. cmd值的F_DUPFD ：
    #F_DUPFD    返回一个如下描述的(文件)描述符：
    #·最小的大于或等于arg的一个可用的描述符
    #·与原始操作符一样的某对象的引用
    #·如果对象是文件(file)的话，则返回一个新的描述符，这个描述符与arg共享相同的偏移量(offset)
    #·相同的访问模式(读，写或读/写)
    #·相同的文件状态标志(如：两个文件描述符共享相同的状态标志)
    #·与新的文件描述符结合在一起的close-on-exec标志被设置成交叉式访问execve(2)的系统调用
    #2. cmd值的F_GETFD和F_SETFD：
    #F_GETFD    取得与文件描述符fd联合的close-on-exec标志，类似FD_CLOEXEC。如果返回值和FD_CLOEXEC进行与运算结果是0的话，文件保持交叉式访问exec()，否则如果通过exec运行的话，文件将被关闭(arg 被忽略)
    #F_SETFD    设置close-on-exec标志，该标志以参数arg的FD_CLOEXEC位决定，应当了解很多现存的涉及文件描述符标志的程序并不使用常数 FD_CLOEXEC，而是将此标志设置为0(系统默认，在exec时不关闭)或1(在exec时关闭)
    #在修改文件描述符标志或文件状态标志时必须谨慎，先要取得现在的标志值，然后按照希望修改它，最后设置新标志值。不能只是执行F_SETFD或F_SETFL命令，这样会关闭以前设置的标志位。

    flags = fcntl.fcntl(fd, fcntl.F_GETFD)
    assert flags != -1
    #FD_CLOEXEC表示当程序执行exec函数后本fd将被系统自动关闭，表示不传递给exec创建的新进程,FD_CLOEXEC用来设置文件的close-on-exec状态标准。在exec()调用后，close-on-exec标志为0的情况，此文件不被关闭。非零则在exec()后被关闭。默认close-on-exec状态为0，需要通过FD_CLOEXEC设置。
    flags |= fcntl.FD_CLOEXEC
    r = fcntl.fcntl(fd, fcntl.F_SETFD, flags)
    assert r != -1
    # There is no platform independent way to implement fcntl(fd, F_SETLK, &fl)
    # via fcntl.fcntl. So use lockf instead
    try:
        #给文件fd加锁。
        #LOCK_UN - 解锁
        #LOCK_SH - 获取共享锁
        #LOCK_EX - 获取独占锁
        #LOCK_NB - 避免阻塞
        #fcntl.lockf(fd, cmd, len=0, start=0, whence=0)。len是要锁定的字节数，start是锁定开始的字节偏移量，相对于whence和whence 与io.IOBase.seek()一样，具体为：
        #0 - 相对于文件的开头（os.SEEK_SET）
        #1 - 相对于当前缓冲位置（os.SEEK_CUR）
        #2 - 相对于文件结尾（os.SEEK_END）
        fcntl.lockf(fd, fcntl.LOCK_EX | fcntl.LOCK_NB, 0, 0, os.SEEK_SET)
    except IOError:
        
        #从文件fd中读取32个字节，r为返回的包含读取字节的字符串
        r = os.read(fd, 32)
        if r:
            logging.error('already started at pid %s' % common.to_str(r))
        else:
            logging.error('already started')
        os.close(fd)
        return -1

    #os.ftruncate(fd, length),将文件fd裁剪成length大小，0也就意味着清空
    os.ftruncate(fd, 0)
    os.write(fd, common.to_bytes(str(pid)))
    return 0

#该方法的大概语义是打开文件f，取得f的文件描述符oldfd.
#获取stream（标准输出、标准错误）的文件描述符newfd.
#关闭newfd文件流
#将oldfd文件描述符对应的内容赋值给newfd
#也就是说将logfile里的内容复制给了标准输出/标准错误
def freopen(f, mode, stream):
    oldf = open(f, mode)
    #fileno()方法返回一个整型的文件描述符
    oldfd = oldf.fileno()
    newfd = stream.fileno()
    os.close(newfd)
    os.dup2(oldfd, newfd)

#该函数启动守护进程
def daemon_start(pid_file, log_file):
    #sys.exit()会引发一个异常：SystemExit，如果这个异常没有被捕获，那么python解释器将会退出。如果有捕获此异常的代码，那么这些代码还是会执行。捕获这个异常可以做一些额外的清理工作。0为正常退出，其他数值（1-127）为不正常，可抛异常事件供捕获 sys.exit()一般用于主线程退出，os._exit()用于fork出的的子进程中退出
    def handle_exit(signum, _):
        if signum == signal.SIGTERM:
            sys.exit(0)
        sys.exit(1)

    #signal.SIGABORT
    #signal.SIGHUP  # 连接挂断
    #signal.SIGILL  # 非法指令
    #signal.SIGINT  # 连接中断
    #signal.SIGKILL # 终止进程（此信号不能被捕获或忽略）
    #signal.SIGQUIT # 终端退出
    #signal.SIGTERM # 终止
    #signal.SIGALRM  # 超时警告
    #signal.SIGCONT  # 继续执行暂停进程
    #设置信号signal.SIGINT处理的函数为handle_exit
    #设置信号signal.SIGTERM处理的函数为handle_exit
    signal.signal(signal.SIGINT, handle_exit)
    signal.signal(signal.SIGTERM, handle_exit)

    # fork only once because we are sure parent will exit
    #os.fork()创建子进程，父进程中返回值是子进程的pid，子进程返回值是0
    pid = os.fork()
    assert pid != -1

    if pid > 0:
        # parent waits for its child
        time.sleep(5)
        sys.exit(0)

    # child signals its parent to exit
    #os.getppid()用于子进程获取自己父进程的pid
    ppid = os.getppid()
    #os.getpid()进程获取自己的pid
    pid = os.getpid()
    if write_pid_file(pid_file, pid) != 0:
        os.kill(ppid, signal.SIGINT)
        sys.exit(1)

    #setsid做三个操作：1. 调用进程成为新会话的首进程，2. 调用进程成为新进程组的组长（组长ID就是调用进程ID），3. 没有控制终端
    #如果调用系统函数setsid的进程是进程组组长的话，将会报错，这也是上面第一步必须要做的原因）
    os.setsid()
    signal.signal(signal.SIG_IGN, signal.SIGHUP)

    print('started')
    os.kill(ppid, signal.SIGTERM)

    sys.stdin.close()
    try:
        freopen(log_file, 'a', sys.stdout)
        freopen(log_file, 'a', sys.stderr)
    except IOError as e:
        shell.print_exception(e)
        sys.exit(1)


def daemon_stop(pid_file):
    import errno
    try:
        with open(pid_file) as f:
            buf = f.read()
            pid = common.to_str(buf)
            if not buf:
                logging.error('not running')
    except IOError as e:
        shell.print_exception(e)
        if e.errno == errno.ENOENT:
            # always exit 0 if we are sure daemon is not running
            logging.error('not running')
            return
        sys.exit(1)
    pid = int(pid)
    if pid > 0:
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as e:
            if e.errno == errno.ESRCH:
                logging.error('not running')
                # always exit 0 if we are sure daemon is not running
                return
            shell.print_exception(e)
            sys.exit(1)
    else:
        logging.error('pid is not positive: %d', pid)

    # sleep for maximum 10s
    for i in range(0, 200):
        try:
            # query for the pid
            os.kill(pid, 0)
        except OSError as e:
            if e.errno == errno.ESRCH:
                break
        time.sleep(0.05)
    else:
        logging.error('timed out when stopping pid %d', pid)
        sys.exit(1)
    print('stopped')
    os.unlink(pid_file)


def set_user(username):
    if username is None:
        return

    import pwd
    import grp

    try:
        pwrec = pwd.getpwnam(username)
    except KeyError:
        logging.error('user not found: %s' % username)
        raise
    user = pwrec[0]
    uid = pwrec[2]
    gid = pwrec[3]

    cur_uid = os.getuid()
    if uid == cur_uid:
        return
    if cur_uid != 0:
        logging.error('can not set user as nonroot user')
        # will raise later

    # inspired by supervisor
    if hasattr(os, 'setgroups'):
        groups = [grprec[2] for grprec in grp.getgrall() if user in grprec[3]]
        groups.insert(0, gid)
        os.setgroups(groups)
    os.setgid(gid)
    os.setuid(uid)
