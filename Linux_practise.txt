#1.求2个数之和
var1=0.2; var2=3; awk -v var1=$var1 -v var2=$var2 'BEGIN{res=var1+var2; print var1 " + " var2 " = " res}'
#2.计算1-100的和
#方法一
awk 'BEGIN{for(i=1;i<=100;i++){sum=sum+i} print sum}'
#方法二
for i in $(seq 100);do sum=$((sum+i));done;echo $sum
#方法三
sum=;for((i=0;i<=100;i++));do sum=$((sum+i));done;echo $sum
#3.将一目录下所有的文件的扩展名改为bak
for file in /etc/*
do
    basename=${file%.*}; mv $file ${basename}.bak
done
#4.编译当前目录下的所有.c文件：
for file in *.c
do
    gcc $file -o ${file%.*}
done
#5.打印root可以使用可执行文件数，处理结果: root's bins: 2306
echo "root's bins: $(find ./ -type f | xargs ls -l | sed '/-..x/p' | wc -l)"
#6.打印当前sshd的端口和进程id，处理结果: sshd Port&&pid: 22 5412
#7.输出本机创建20000个目录所用的时间，处理结果:
#
#real    0m3.367s
#user    0m0.066s
#sys     0m1.925s
time for i in $(seq 20000); do mkdir /tmp/folder${i}; done
#8.打印本机的交换分区大小，处理结果: Swap:1024M
#
#9.本分析，取出/etc/password中shell出现的次数
#
#第一种方法结果:
#      4 /bin/bash
#      1 /bin/sync
#      1 /sbin/halt
#     31 /sbin/nologin
#      1 /sbin/shutdown
#第二种方法结果:
#        /bin/sync       1
#        /bin/bash       1
#        /sbin/nologin   30
#        /sbin/halt      1
#        /sbin/shutdown  1
cat /etc/passwd | awk 'BEGIN{ FS=":"} {print $7}' | sort | uniq -c
#10.文件整理，employee文件中记录了工号和姓名,（提示join）
#
#employee.txt:
#    100 Jason Smith 
#    200 John Doe 
#    300 Sanjay Gupta 
#    400 Ashok Sharma 
#    bonus文件中记录工号和工资
#bonus.txt:
#    100 $5,000 
#    200 $500 
#    300 $3,000 
#    400 $1,250 
#要求把两个文件合并并输出如下，处理结果:
#    400 ashok sharma $1,250
#    100 jason smith  $5,000
#    200 john doe  $500
#    300 sanjay gupta  $3,000
join employee bonus | sort -k 2
#11.写一个shell脚本来得到当前的日期，时间，用户名和当前工作目录。
echo $(date +"%Y-%m-%d %H:%M:%S")
echo $(date +"%D %T")
echo $(whoami)
echo $(pwd)
#12.编写shell脚本获取本机的网络地址。
ifconfig eth0 | grep "inet addr" | awk '{ print $2}' | awk -F: '{print $2}'
#13.编写个shell脚本将当前目录下大于10K的文件转移到/tmp目录下
find /var  -size +10k -type f -exec mv {} /tmp \;
#14.编写一个名为myfirstshell.sh的脚本，它包括以下内容。
#a) 包含一段注释，列出您的姓名、脚本的名称和编写这个脚本的目的。
#b) 问候用户。
#c) 显示日期和时间。
#d) 显示这个月的日历。
#e) 显示您的机器名。
#f) 显示当前这个操作系统的名称和版本。
#g) 显示父目录中的所有文件的列表。
#h) 显示root正在运行的所有进程。
#i) 显示变量TERM、PATH和HOME的值。
#j) 显示磁盘使用情况。
#k) 用id命令打印出您的组ID。
#m) 跟用户说“Good bye”
# !bin/bash
# ----------------------------------------------------------------------
# name:			myfirstshell.sh
# version:		1.0
# createTime:	2018-06-12
# description:	shell脚本练习
# author:		Ciara
# email:		924417727@qq.com
# ----------------------------------------------------------------------
echo "Hello"
date
cal
hostname
uname -s;uname -v
ls ../*
ps -u root
echo "TERM is $TERM , PATH is $PATH , HOME is $HOME ."
df
id -g
echo "Good bye"
#15.文件移动拷贝，有m1.txt m2.txt m3.txt m4.txt，分别创建出对应的目录，m1 m2 m3 m4 并把文件移动到对应的目录下
#16.root用户今天登陆了多长时间
#17.终端输入一个文件名，判断是否是设备文件
#18.统计IP访问：要求分析apache访问日志，找出访问页面数量在前100位的IP数。日志大小在78M左右。以下是apache的访问日志节选
#202.101.129.218 - - [26/Mar/2006:23:59:55 +0800] "GET /online/stat_inst.php?pid=d065 HTTP/1.1" 302 20-"-" "-" "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)"
awk '{print $1}' apache_log |sort |uniq -c|sort -nr|head -n 10
#19.设计一个Shell程序，在/userdata目录下建立50个目录，即user1～user50，并设置每个目录的权限，其中其他用户的权限为：读；文件所有者的权限为：读、写、执行；文件所有者所在组的权限为：读、执行。
for i in $(seq 50)
do
    mkdir /tmp/usr$i
	chmod 754 /tmp/usr$i 
	ls /tmp/usr$i 
done
#20.设计一个shell程序，添加一个新组为class1，然后添加属于这个组的30个用户，用户名的形式为stdxx，其中xx从01到30，并设置密码为对应的stdxx。
groupadd class1
for i in $(seq 30)
do
    if((i<10))
	then
	    i="0"$i
	fi
	useradd -g class1  std$i
done
#21.编写shell程序，实现自动删除30个账号的功能。账号名为std01至std30。
for i in $(seq 30)
do
    if((i<10))
	then
	    i="0"$i
	fi
	userdel  std$i
done
#22.用户清理,清除本机除了当前登陆用户以外的所有用户
#23.设计一个shell程序，在每月第一天备份并压缩/etc目录的所有内容，存放在/root/bak目录里，且文件名,为如下形式yymmdd_etc，yy为年，mm为月，dd为日。Shell程序fileback存放在/usr/bin目录下。
#24.对于一个用户日志文件，每行记录了一个用户查询串，长度为1-255字节，共几千万行，请排出查询最多的前100条。 日志可以自己构造。 (提示：awk sort uniq head)
awk 'BEGIN{FS=":"}{print $7}' /etc/passwd | sort  | uniq -c | sort -nr | head -n 100
#25.编写自己的ubuntu环境安装脚本
#26.编写服务器守护进程管理脚本。
#27.查看TCP连接状态
netstat -nat |awk ‘{print $6}’|sort|uniq -c|sort -rn

netstat -n | awk ‘/^tcp/ {++S[$NF]};END {for(a in S) print a, S[a]}’ 或
netstat -n | awk ‘/^tcp/ {++state[$NF]}; END {for(key in state) print key,"\t",state[key]}’
netstat -n | awk ‘/^tcp/ {++arr[$NF]};END {for(k in arr) print k,"t",arr[k]}’

netstat -n |awk ‘/^tcp/ {print $NF}’|sort|uniq -c|sort -rn

netstat -ant | awk ‘{print $NF}’ | grep -v ‘[a-z]‘ | sort | uniq -c
#28.查找请求数请20个IP（常用于查找攻来源）：

netstat -anlp|grep 80|grep tcp|awk ‘{print $5}’|awk -F: ‘{print $1}’|sort|uniq -c|sort -nr|head -n20

netstat -ant |awk ‘/:80/{split($5,ip,":");++A[ip[1]]}END{for(i in A) print A[i],i}’ |sort -rn|head -n20
#29.用tcpdump嗅探80端口的访问看看谁最高

tcpdump -i eth0 -tnn dst port 80 -c 1000 | awk -F"." ‘{print $1"."$2"."$3"."$4}’ | sort | uniq -c | sort -nr |head -20
#30.查找较多time_wait连接

netstat -n|grep TIME_WAIT|awk ‘{print $5}’|sort|uniq -c|sort -rn|head -n20
#31.找查较多的SYN连接

netstat -an | grep SYN | awk ‘{print $5}’ | awk -F: ‘{print $1}’ | sort | uniq -c | sort -nr | more
#32.根据端口列进程

netstat -ntlp | grep 80 | awk ‘{print $7}’ | cut -d/ -f1
#33.获得访问前10位的ip地址

cat access.log|awk ‘{print $1}’|sort|uniq -c|sort -nr|head -10
cat access.log|awk ‘{counts[$(11)]+=1}; END {for(url in counts) print counts[url], url}’
#34.访问次数最多的文件或页面,取前20

cat access.log|awk ‘{print $11}’|sort|uniq -c|sort -nr|head -20
#35.列出传输最大的几个exe文件（分析下载站的时候常用）

cat access.log |awk ‘($7~/.exe/){print $10 " " $1 " " $4 " " $7}’|sort -nr|head -20
#36.列出输出大于200000byte(约200kb)的exe文件以及对应文件发生次数

cat access.log |awk ‘($10 > 200000 && $7~/.exe/){print $7}’|sort -n|uniq -c|sort -nr|head -100
#37.如果日志最后一列记录的是页面文件传输时间，则有列出到客户端最耗时的页面

cat access.log |awk ‘($7~/.php/){print $NF " " $1 " " $4 " " $7}’|sort -nr|head -100
#38.列出最最耗时的页面(超过60秒的)的以及对应页面发生次数

cat access.log |awk ‘($NF > 60 && $7~/.php/){print $7}’|sort -n|uniq -c|sort -nr|head -100
#39.列出传输时间超过 30 秒的文件

cat access.log |awk ‘($NF > 30){print $7}’|sort -n|uniq -c|sort -nr|head -20
#40.统计网站流量（G)

cat access.log |awk ‘{sum+=$10} END {print sum/1024/1024/1024}’
#41.统计404的连接

awk ‘($9 ~/404/)’ access.log | awk ‘{print $9,$7}’ | sort
#42.统计http status

cat access.log | awk '{counts[$(9)]+=1}; END {for(code in counts) print code, counts[code]}'
cat access.log | awk '{print $9}'|sort|uniq -c|sort -rn
#43.蜘蛛分析，查看是哪些蜘蛛在抓取内容。

/usr/sbin/tcpdump -i eth0 -l -s 0 -w - dst port 80 | strings | grep -i user-agent | grep -i -E 'bot|crawler|slurp|spider'
#44.创建一个用户mandriva，其ID号为2002，基本组为distro（组ID为3003），附加组为linux；

 groupadd linux
 groupadd -g 3003 distro
 useradd -u 2002 -g distro -G linux mandriva
#45.创建一个用户fedora，其全名为Fedora Community，默认shell为tcsh； 
 useradd -c "Fedora Community" -s /bin/tcsh fedora

#46.修改mandriva的ID号为4004，基本组为linux，附加组为distro和fedora；

 usermod -u 4004 -g linux -G distro,fedora mandriva
#47.给fedora加密码，并设定其密码最短使用期限为2天，最长为50天；

passwd fedora
chage -m 2 -M 50 fedora
#48.调试命令

strace -p pid
#49.写一个脚本
#
#1、创建一个组newgroup, id号为4000；
#2、创建一个用户mageedu1, id号为3001，附加组为newgroup；
#3、创建目录/tmp/hellodirxyz
#4、复制/etc/fstab至上面的目录中
#5、改变目录及内部文件的属主和属组为mageedu1;
#6、让目录及内部文件的其它用户没有任何权限；

        #!/bin/bash
        # Description:
        # Version:
        # Datetime:
        # Author:

        myGroup="newgroup1"
        myUser="mageedu2"
        myDir="/tmp/hellodirxyz1"
        myID=3002

        groupadd -g 4001 $myGroup
        useradd -u $myID -G $myGroup $myUser
        mkdir $myDir
        cp /etc/fstab $myDir
        chown -R $myUser:$myUser $myDir
        chmod -R o= $myDir

        unset myGroup myUser myID myDir
#50.统计/bin、/usr/bin、/sbin和/usr/sbin等各目录中的文件个数；

ls /bin | wc -l
#51.显示当前系统上所有用户的shell，要求，每种shell只显示一次；

cut -d: -f7 /etc/passwd | sort -u
#52.取出/etc/passwd文件的第7行；

head -7 /etc/passwd | tail -1
#53.显示第3题中取出的第7行的用户名；

head -7 /etc/passwd | tail -1 | cut -d: -f1

head -7 /etc/passwd | tail -1 | cut -d: -f1 | tr 'a-z' 'A-Z'
#54.统计/etc目录下以P或p开头的文件个数；

ls -d /etc/[Pp]* | wc -l
#55.写一个脚本，用for循环实现显示/etc/init.d/functions、/etc/rc.d/rc.sysinit和/etc/fstab各有多少行；

for fileName in /etc/init.d/functions /etc/rc.d/rc.sysinit /etc/fstab; do
    wc -l $fileName
done

#!/bin/bash
for fileName in /etc/init.d/functions /etc/rc.d/rc.sysinit /etc/fstab; do
    lineCount=`wc -l $fileName | cut -d' ' -f1`
    echo "$fileName: $lineCount lines."
done

#!/bin/bash
for fileName in /etc/init.d/functions /etc/rc.d/rc.sysinit /etc/fstab; do
    echo "$fileName: `wc -l $fileName | cut -d' ' -f1` lines."
done
#56.写一个脚本,将上一题中三个文件的复制到/tmp目录中；用for循环实现，分别将每个文件的最近一次的修改时间改为2016年12月15号15点43分；

for fileName in /etc/init.d/functions /etc/rc.d/rc.sysinit /etc/fstab; do
    cp $fileName /tmp
    baseName=`basename $fileName`
    touch -m -t 201109151327 /tmp/$baseName
done
#57.写一个脚本, 显示/etc/passwd中第3、7和11个用户的用户名和ID号；
for i in 3 7 11
do
    awk -v i=$i 'BEGIN{FS=":"} NR==i{print "第"i"个用户的用户名是"$1", id号是"$3"." }' /etc/passwd
done
#58.显示/proc/meminfo文件中以大小写s开头的行；
grep -i '^s' /proc/meminfo
#59.取出默认shell为非bash的用户；
grep -v 'bash' /etc/passwd | cut -d: -f1
#60.取出默认shell为bash的且其ID号最大的用户；
awk 'BEGIN{FS=":"}/bash/{print $3}' /etc/passwd | sort -nr | head -n 1
#61.显示/etc/rc.d/rc.sysinit文件中，以#开头，后面跟至少一个空白字符，而后又有至少一个非空白字符的行；
grep "^#[[:space:]]\{1,\}[^[:space:]]\{1,\}" /etc/rc.d/rc.sysinit
#62.显示/boot/grub/grub.conf中以至少一个空白字符开头的行；
grep '[[:space:]]\{1,\}' /boot/grub/grub.conf
#63.找出/etc/passwd文件中一位数或两位数；
grep '[^[:digit:]][[:digit:]]\{1,2\}[^[:digit:]]' /etc/passwd
grep  "\<[0-9]\{1,2\}\>" /etc/passwd 
grep -w '[[:digit:]]\{1,2\}' /etc/passwd 
#64.找出ifconfig命令结果中的1到255之间的整数；
ifconfig | grep -E --color=auto "\<([1-9]|[1-9][0-9]|1[0-9]\{2\}|2[0-4][0-9]|25[0-5])\>"
#65.查看当前系统上root用户的所有信息
grep "^root\>" /etc/passwd
#66.添加用户bash和testbash、basher，而后找出当前系统上其用户名和默认shell相同的用户；
grep --color=auto "^\([[:alnum:]]\{1,\}\)\>.*\1$" /etc/passwd
#67.找出netstat -tan命令执行的结果中以“LISTEN”或“ESTABLISHED”结尾的行
netstat -tan | grep '\(LISTEN\|ESTABLISHED\)$'
#68.取出当前系统上所有用户的shell，要求：每种shell只显示一次，且按升序显示；
awk 'BEGIN{FS=":"}{print $NF}' /etc/passwd | sort -u
#69.用Shell编程，判断一文件是不是块或字符设备文件，如果是将其拷贝到 /dev 目录下。 
echo -e "The program will Judge a file is or not a device file./n/n"
read -p "Input a filename : " filename
if [ -b "$filename" -o -c "$filename" ]
then
       echo "$filename is a device file" && cp $filename /dev/ &
else
       echo "$filename is not a device file" && exit 1
fi
#70.设计一个shell程序，在每月第一天备份并压缩/etc目录的所有内容，存放在/root/bak目录里，且文件名
#为如下形式yymmdd_etc，yy为年，mm为月，dd为日。Shell程序fileback存放在/usr/bin目录下。
vim /usr/bin/fileback.sh

#!/bin/bash
#fileback.sh
#file executable: chmod 755 fileback.sh
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
filename=`date +%y%m%d`_etc.tar.gz
cd /etc/
tar -zcvf $filename *
mv $filename /root/bak/
------------------------------------------------------
vim /etc/crontab 加入
* * 1 * * root ./fileback.sh &
#71.打印本机的交换分区大小。处理结果:Swap:1024M
free -m | sed -n '/Swap/p' | awk '{ print $2}'
free -m | sed -n 's/Swap:/ */([0-9]*/).*//1/p'
#72.将当前计算机的IP地址设为192.168.1.123，子网掩码为255.255.255.0.
config eth0 192.168.1.123 netmask 255.255.255.0.
#73.让named 守护进程运行在级别3,5的命令
telinit 3; telinit 5
#74.更改用户zhang的登录shell为/sbin/nologin
usermod -s /sbin/nologin zhang
#75.查看当前Linux服务器的额主机名的命令
cat /proc/sys/kernel/hostname
或sysctl kernel.hostname
或hostname
#76.查看当前主机的路由的命令
route
#77.让named 守护进程运行级别3,5的命令
telinit 3;telinit 5
#78.配置当前主机的默认网关为192.168.2.254
route add defalut gw 192.168.2.254
#79.连续ping目的IP为192.168.2.245为10次的命令
ping -c 10 192.168.2.245
#80.查看当前主机TCP协议链接情况的命令
netstat -t
#81.打包并压缩/etc目录的命令
tar -jcvf mylinux_etc.tar.bz2 /etc/
tar -zcvf mylinux_etc.tar.gz /etc/
#82.测试httpd是否安装的命令
rpm -q httpd
#83.卸载named 软件包的命令
rpm -e named 
#84.重启samba服务的命令。 
service smb restart
#85.查看进程状态的命令。 
ps -aux
#86.列出后台作业的命令。 
jobs -l
#87.将作业ID为5的后台作业放到前台的命令。 
fg 5
#88.停止ssh服务的命令。 
service sshd stop
#89.重启linux服务器的命令。 
shutdown -r now
#90.显示操作系统核心版本详细信息的命令。 
uname -a
#91.从IP地址查找域名或从域名来查找IP地址应使用什么命令。 
host
#92.查看Linux的启动信息的命令。 
dmesg
#93.写出系统1分钟后关机的命令。 
shutdown –s –t 60
#94.后台启动程序gedit。 
Gedit &
#95.查看dns服务器的状态。 
pstree |grep named
#96.设置当前时间设为15:00,显示当前系统时间。 
date –s “15:00”
#97.查看DHCP服务器的状态。 
service dhcpd status
#98.打印杨辉三角
方法一：
echo "1"
for ((i=2;i<=$1;i++))
do
	curr[0]=1
	for((j=1;j<=i-2;j++))
	do
		curr[$j]=$((num[$j-1]+num[$j]))
	done
	curr[$i-1]=1
	echo ${curr[*]}
	num=(${curr[*]})
done
方法二
for ((i=1;i<=$1;i++))
do
	a[0]=1
	for((j=i-1;j>0;j--))
	do
		((a[$j]=a[$j]+a[$j-1]))
	done
	echo ${curr[*]}
done










