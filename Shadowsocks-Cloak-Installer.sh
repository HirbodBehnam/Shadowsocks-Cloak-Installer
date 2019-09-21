#!/bin/bash
num_regex='^[0-9]+$'
function GetRandomPort() {
	PORT=$((RANDOM % 16383 + 49152))
}
function ShowConnectionInfo() {
	echo "Your Server IP: $PUBLIC_IP"
	echo "Password:       $Password"
	echo "Port:           $PORT"
	echo "Encryption:     $cipher"
	if [ $1 == true ]; then
		echo "Cloak UID (Admin ID): $ckauid"
	else
		echo "Cloak UID:            $ckauid"
	fi
	echo "Cloak Public Key:     $ckpub"
	echo "Cloak Server Name:    Use the domain of $ckwebaddr,if untouched use bing.com"
	echo "Cloak TicketTimeHint: Leave default(3600)"
	echo "Cloak NumConn:        4 or more"
	echo "Cloak MaskBrowser:    firefox or chrome"
	echo "Also read more about these arguments at https://github.com/cbeuw/Cloak#client"
	echo
	echo "Download cloak client for android from https://github.com/cbeuw/Cloak-android/releases"
	echo "Download cloak client for PC from https://github.com/cbeuw/Cloak/releases"
	echo
	echo
	echo
	ckpub=${ckpub::-1}
	ckpub+="\\="
	ckauid=${ckauid::-1}
	ckauid+="\\="
	SERVER_BASE64=$(printf "%s" "$cipher:$Password" | base64)
	SERVER_CLOAK_ARGS="ck-client;UID=$ckauid;PublicKey=$ckpub;ServerName=$ckwebaddr;TicketTimeHint=3600;MaskBrowser=chrome;NumConn=4"
	SERVER_CLOAK_ARGS=$(printf "%s" "$SERVER_CLOAK_ARGS" | curl -Gso /dev/null -w %{url_effective} --data-urlencode @- "" | cut -c 3-) #https://stackoverflow.com/a/10797966/4213397
	SERVER_BASE64="ss://$SERVER_BASE64@$PUBLIC_IP:$PORT?plugin=$SERVER_CLOAK_ARGS"
	qrencode -t ansiutf8 "$SERVER_BASE64"
	echo
	echo
	echo "Or just use this string: $SERVER_BASE64"
}
function PreAdminConsolePrint() {
	clear
	echo "$(tput setaf 3)PLEASE READ THIS BEFORE CONTINUING$(tput sgr 0)"
	echo "The steps here are semi-automated. You have to enter some values yourself. Please read all of the instructions on screen then continue."
	echo
	echo "At first application wants you to enter the IP and Port of your server. Enter this:"
	echo "$(tput setaf 3)127.0.0.1:$PORT$(tput sgr 0)"
	echo "Then you will be asked for Admin UID. Enter this:"
	echo "$(tput setaf 3)$ckauid$(tput sgr 0)"
	echo "Now you will enter the admin panel."
}
if [[ "$EUID" -ne 0 ]]; then #Check root
	echo "Please run this script as root"
	exit 1
fi
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
if [ -d "/etc/shadowsocks-libev" ]; then
	echo "Looks like you have installed shadowsocks. Choose an option below:"
	echo "1) Show Connection Info for Admin"
	echo "2) User Management"
	echo "3) Regenerate Firewall Rules"
	echo "4) Uninstall Shadowsocks"
	read -r -p "Please enter a number: " OPTION
	cd /etc/shadowsocks-libev || exit 2
	PORT=$(jq -r '.server_port' <'config.json')
	case $OPTION in
	1)
		cipher=$(jq -r '.method' <'config.json')
		Password=$(jq -r '.password' <'config.json')
		PUBLIC_IP="$(curl https://api.ipify.org -sS)"
		CURL_EXIT_STATUS=$?
		if [ $CURL_EXIT_STATUS -ne 0 ]; then
			PUBLIC_IP="YOUR_IP"
		fi
		ckauid=$(jq -r '.AdminUID' <'ckconfig.json')
		ckwebaddr=$(jq -r '.WebServerAddr' <'ckconfig.json')
		ckpub=$(jq -r '.PublicKey' <'ckclient.json')
		ShowConnectionInfo true
		;;
	2)
		ckauid=$(jq -r '.AdminUID' <'ckconfig.json')
		echo "1) Show Connection Info for User"
		echo "2) Add User"
		echo "3) Revoke User"
		echo "4) Open Console Admin"
		read -r -p "Please enter a number: " OPTION
		case $OPTION in
		1)
			Users=()
			i=1
			while IFS= read -r line; do
				Users+=("$line")
				echo "$i) $line"
				i=$((i + 1))
			done <"usersForScript.txt"
			if [ ${#Users[@]} -eq 0 ]; then
				echo "No users created!"
				exit 0
			fi
			read -r -p "Choose a username by number to continue: " OPTION
			i=$((i - 1))
			if [ "$OPTION" -gt $i ] || [ "$OPTION" -lt 1 ]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0): Number must be between 1 and $i"
				exit 1
			fi
			OPTION=$((OPTION - 1))
			IN=${Users[$OPTION]}
			arrIN=(${IN//:/ })
			cipher=$(jq -r '.method' <'config.json')
			Password=$(jq -r '.password' <'config.json')
			PUBLIC_IP="$(curl https://api.ipify.org -sS)"
			CURL_EXIT_STATUS=$?
			if [ $CURL_EXIT_STATUS -ne 0 ]; then
				PUBLIC_IP="YOUR_IP"
			fi
			ckauid=${arrIN[1]}
			ckwebaddr=$(jq -r '.WebServerAddr' <'ckconfig.json')
			ckpub=$(jq -r '.PublicKey' <'ckclient.json')
			ShowConnectionInfo false
			;;
		2)
			read -r -p "Enter a username for your user: " NewUserNickname
			NewUserID=$(ck-server -u)
			read -r -p "How many days this user can use the script? [1~3650]: " -e -i 365 ValidDays
			if ! [[ $ValidDays =~ $num_regex ]]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0) The input is not a valid number"
				exit 1
			fi
			if [ "$ValidDays" -gt 3650 ] || [ "$ValidDays" -lt 1 ]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0): Number must be between 1 and 3650"
				exit 1
			fi
			Now=$(date +%s)
			ValidDays=$((ValidDays * 86400))
			ValidDays=$((ValidDays + Now))
			PreAdminConsolePrint
			echo "Type $(tput setaf 3)4$(tput sgr 0) at panel and press enter."
			echo "Enter $(tput setaf 3)$NewUserID$(tput sgr 0) as UID."
			echo "SessionsCap is maximum amount of concurrent sessions a user can have. In other words, number of concurrent connections a user can have."
			echo "$(tput setaf 3)DO NOT COPY AND PASTE THESE NUMBER$(tput sgr 0)"
			echo "UpRate is maximum upload speed for user in byte/s"
			echo "DownRate is maximum download speed for user in byte/s"
			echo "UpCredit is maximum amount of bytes user can upload."
			echo "DownCredit is maximum amount of bytes user can download."
			echo "For ExpiryTime, enter $(tput setaf 3)$ValidDays$(tput sgr 0)"
			echo "Then press Ctrl+C to exit admin panel"
			echo
			read -r -p "READ ALL ABOVE then press enter to continue..."
			trap "echo Process Exited." SIGINT
			ck-client -a -c ckclient.json
			echo
			read -r -p "The admin panel exited; Was the process successful or not? (Did you see a \"ok\"?) [y/n]" Result
			if [ "$Result" == "y" ]; then
				echo "Great!"
				echo "$NewUserNickname:$NewUserID" >>usersForScript.txt
			elif [ "$Result" == "n" ]; then
				echo "Ops!"
				echo "You can re run the script to re-create the user."
				echo "If you believe there is a bug in script open an issue here: https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer/issues"
				echo "If you think that the bug is from Cloak, open an issue here: https://github.com/cbeuw/Cloak/issues"
			fi
			;;
		3)
			Users=()
			i=1
			while IFS= read -r line; do
				Users+=("$line")
				echo "$i) $line"
				i=$((i + 1))
			done <"usersForScript.txt"
			if [ ${#Users[@]} -eq 0 ]; then
				echo "No users created!"
				exit 0
			fi
			read -r -p "Choose a username by number to continue: " OPTION
			i=$((i - 1))
			if [ "$OPTION" -gt $i ] || [ "$OPTION" -lt 1 ]; then
				echo "$(tput setaf 1)Error:$(tput sgr 0): Number must be between 1 and $i"
				exit 1
			fi
			OPTION=$((OPTION - 1))
			IN=${Users[$OPTION]}
			arrIN=(${IN//:/ })
			PreAdminConsolePrint
			echo "Type $(tput setaf 3)5$(tput sgr 0) at panel and press enter."
			echo "Enter $(tput setaf 3)${arrIN[1]}$(tput sgr 0) as UID."
			echo "Choose y and press enter."
			echo "Then press Ctrl+C to exit admin panel"
			echo
			read -r -p "READ ALL ABOVE then press enter to continue..."
			trap "echo Process Exited." SIGINT
			ck-client -a -c ckclient.json
			echo
			read -r -p "The admin panel exited; Was the process successful or not? (Did you see a \"ok\"?) [y/n]" Result
			if [ "$Result" == "y" ]; then
				echo "Great!"
				rm usersForScript.txt
				touch usersForScript.txt
				for i in "${Users[@]}"; do
					if [ "$i" != "$IN" ]; then
						echo "$i" >>usersForScript.txt
					fi
				done
			elif [ "$Result" == "n" ]; then
				echo "Ops!"
				echo "You can re run the script to retry to remove the user."
				echo "If you believe there is a bug in script open an issue here: https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer/issues"
				echo "If you think that the bug is from Cloak, open an issue here: https://github.com/cbeuw/Cloak/issues"
			fi
			;;
		4)
			PreAdminConsolePrint
			echo "Exit admin panel with Ctrl+C"
			echo
			read -r -p "Press enter to continue..."
			ck-client -a -c ckclient.json
			;;
		esac
		;;
	3)
		if [[ $distro =~ "CentOS" ]]; then
			echo "firewall-cmd --add-port=$PORT/tcp"
			echo "firewall-cmd --permanent --add-port=$PORT/tcp"
		elif [[ $distro =~ "Ubuntu" ]]; then
			echo "ufw allow $PORT/tcp"
		elif [[ $distro =~ "Debian" ]]; then
			echo "iptables -A INPUT -p tcp --dport $PORT --jump ACCEPT"
			echo "iptables-save"
		fi
		;;
	4)
		read -r -p "I still keep some packages like \"qrencode\". Do want to uninstall Shadowsocks?(y/n) " OPTION
		if [ "$OPTION" == "y" ] || [ "$OPTION" == "Y" ]; then
			systemctl stop shadowsocks-server
			systemctl disable shadowsocks-server
			rm -f /etc/systemd/system/shadowsocks-server.service
			systemctl daemon-reload
			if [[ $distro =~ "CentOS" ]]; then
				yum -y remove shadowsocks-libev
				firewall-cmd --remove-port="$PORT"/tcp
				firewall-cmd --permanent --remove-port="$PORT"/tcp
			elif [[ $distro =~ "Ubuntu" ]]; then
				apt-get -y purge shadowsocks-libev
				ufw delete allow "$PORT"/tcp
			elif [[ $distro =~ "Debian" ]]; then
				apt-get -y purge shadowsocks-libev
				iptables -D INPUT -p tcp --dport "$PORT" --jump ACCEPT
				iptables-save >/etc/iptables/rules.v4
			fi
			rm -rf /etc/shadowsocks-libev
			rm -f /usr/local/bin/ck-server
			rm -f /usr/local/bin/ck-client
			echo "Done"
			echo "Please reboot the server for a clean uninstall."
		fi
		;;
	esac
	exit 0
fi
ciphers=(rc4-md5 aes-128-gcm aes-192-gcm aes-256-gcm aes-128-cfb aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr camellia-128-cfb camellia-192-cfb camellia-256-cfb bf-cfb chacha20-ietf-poly1305 xchacha20-ietf-poly1305 salsa20 chacha20 chacha20-ietf)
clear
echo "Shadowsocks with Cloak installer by Hirbod Behnam"
echo "Source at https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer"
echo "Shadowsocks-libev at https://github.com/shadowsocks/shadowsocks-libev"
echo "Cloak at https://github.com/cbeuw/Cloak"
echo
echo
#Get port
read -r -p "Please enter a port to listen on it. 443 is recommended. Enter -1 for a random port: " -e -i 443 PORT
if [[ $PORT -eq -1 ]]; then #Check random port
	GetRandomPort
	echo "I've selected $PORT as your port."
fi
if ! [[ $PORT =~ $num_regex ]]; then #Check if the port is valid
	echo "$(tput setaf 1)Error:$(tput sgr 0) The input is not a valid number"
	exit 1
fi
if [ "$PORT" -gt 65535 ]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0): Number must be less than 65536"
	exit 1
fi
#Get password
read -r -p "Enter a password for shadowsocks. Leave blank for a random password: " Password
if [ "$Password" == "" ]; then
	Password=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1) #https://gist.github.com/earthgecko/3089509
	echo "$Password was chosen."
fi
#Get cipher
default_port=15
if [[ $distro =~ "Debian" ]]; then
	ver=$(cat /etc/debian_version)
	ver="${ver:0:1}"
	if [ "$ver" == "8" ]; then
		default_port=2
		ciphers=(rc4-md5 aes-128-cfb aes-192-cfb aes-256-cfb aes-128-ctr aes-192-ctr aes-256-ctr bf-cfb camellia-128-cfb camellia-192-cfb camellia-256-cfb salsa20 chacha20)
	fi
fi
echo
for ((i = 0; i < ${#ciphers[@]}; i++)); do
	echo "$((i + 1))) ${ciphers[$i]}"
done
read -r -p "Enter the number of cipher you want to use: " -e -i $default_port cipher
if [ "$cipher" -lt 1 ] || [ "$cipher" -gt 18 ]; then
	echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
	exit 1
fi
cipher=${ciphers[$cipher - 1]}
#Get DNS server
echo
echo "1) Cloudflare"
echo "2) Google"
echo "3) OpenDNS"
echo "4) Custom"
read -r -p "Which DNS server you want to use? " -e -i 1 dns
case $dns in
'1')
	dns="1.1.1.1"
	;;
'2')
	dns="8.8.8.8"
	;;
'3')
	dns="208.67.222.222"
	;;
'4')
	read -r -p "Please enter your dns server address(One IP only): " -e -i "1.1.1.1" dns
	;;
*)
	echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
	exit 1
	;;
esac
#Set redirect ip for cloak; Just like https://gist.github.com/cbeuw/37a9d434c237840d7e6d5e497539c1ca#file-shadowsocks-ck-release-sh-L165
echo -e "Please enter a redirection IP for Cloak (leave blank to set it to 204.79.197.200:443 of bing.com): "
read -r -p "" ckwebaddr
[ -z "$ckwebaddr" ] && ckwebaddr="204.79.197.200:443"
#Check arch
arch=$(uname -m)
case $arch in
"i386" | "i686") ;;

"x86_64")
	arch=2
	;;
*)
	if [[ "$arch" =~ "armv" ]]; then
		arch=${arch:4:1}
		if [ "$arch" -gt 7 ]; then
			arch=4
		else
			arch=3
		fi
	else
		arch=0
	fi
	;;
esac
if [ "$arch" == "0" ]; then
	arch=1
	echo "$(tput setaf 3)Warning!$(tput sgr 0) Cannot automatically determine architecture."
fi
echo "1) 386"
echo "2) amd64"
echo "3) arm"
echo "4) arm64"
read -r -p "Select your architecture: " -e -i $arch arch
case $arch in
1)
	arch="386"
	;;
2)
	arch="amd64"
	;;
3)
	arch="arm"
	;;
4)
	arch="arm64"
	;;
*)
	echo "$(tput setaf 1)Error:$(tput sgr 0) Invalid option"
	exit 1
	;;
esac
#Install shadowsocks
if [[ $distro =~ "CentOS" ]]; then
	yum -y install epel-release yum-utils
	yum-config-manager --add-repo https://copr.fedorainfracloud.org/coprs/librehat/shadowsocks/repo/epel-7/librehat-shadowsocks-epel-7.repo
	yum -y install shadowsocks-libev wget jq qrencode curl haveged
	SETFIREWALL=true
	if ! yum -q list installed firewalld &>/dev/null; then
		echo
		read -r -p "Looks like \"firewalld\" is not installed Do you want to install it?(y/n) " -e -i "y" OPTION
		OPTION="$(echo $OPTION | tr '[A-Z]' '[a-z]')"
		case $OPTION in
		"y" | "Y")
			yum -y install firewalld
			systemctl enable firewalld
			;;
		*)
			SETFIREWALL=false
			;;
		esac
	fi
	if [ "$SETFIREWALL" = true ]; then
		systemctl start firewalld
		firewall-cmd --zone=public --add-port="$PORT"/tcp
		firewall-cmd --runtime-to-permanent
	fi
elif [[ $distro =~ "Ubuntu" ]]; then
	if [[ $(lsb_release -r -s) =~ "18" ]] || [[ $(lsb_release -r -s) =~ "19" ]]; then
		apt update
		apt -y install shadowsocks-libev wget jq qrencode curl haveged
		#Use BBR on user will
		if ! [ "$(sysctl -n net.ipv4.tcp_congestion_control)" = "bbr" ]; then
			echo
			read -r -p "Do you want to use BBR?(y/n) " -e -i "y" OPTION
			case $OPTION in
			"y" | "Y")
				echo 'net.core.default_qdisc=fq' | tee -a /etc/sysctl.conf
				echo 'net.ipv4.tcp_congestion_control=bbr' | tee -a /etc/sysctl.conf
				sysctl -p
				;;
			esac
		fi
	else
		apt-get install software-properties-common -y
		add-apt-repository ppa:max-c-lv/shadowsocks-libev -y
		apt-get update
		apt-get -y install shadowsocks-libev wget jq qrencode curl haveged
	fi
	if dpkg --get-selections | grep -q "^ufw[[:space:]]*install$" >/dev/null; then
		ufw allow "$PORT"/tcp
	else
		echo
		read -r -p "Looks like \"UFW\"(Firewall) is not installed Do you want to install it?(y/n) " -e -i "y" OPTION
		case $OPTION in
		"y" | "Y")
			apt-get install ufw
			ufw enable
			ufw allow ssh
			ufw allow "$PORT"/tcp
			;;
		esac
	fi
elif [[ $distro =~ "Debian" ]]; then
	ver=$(</etc/debian_version)
	ver="${ver%.*}"
	if [ "$ver" == "8" ]; then
		sh -c 'printf "deb [check-valid-until=no] http://archive.debian.org/debian jessie-backports main\n" > /etc/apt/sources.list.d/jessie-backports.list' #https://unix.stackexchange.com/a/508728/331589
		echo "Acquire::Check-Valid-Until \"false\";" >>/etc/apt/apt.conf
		apt-get update
		apt -y -t jessie-backports install shadowsocks-libev
	elif [ "$ver" == "9" ]; then
		sh -c 'printf "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/stretch-backports.list'
		apt update
		apt -t stretch-backports install shadowsocks-libev
	elif [ "$ver" == "10" ]; then
		sh -c 'printf "deb http://deb.debian.org/debian buster-backports main" > /etc/apt/sources.list.d/stretch-backports.list'
		apt update
		apt -t buster-backports install shadowsocks-libev
	else
		echo "Your debian is too old!"
		exit 2
	fi
	apt -y install wget jq qrencode curl iptables-persistent iptables haveged
	#Firewall
	iptables -A INPUT -p tcp --dport "$PORT" --jump ACCEPT
	iptables-save >/etc/iptables/rules.v4
else
	echo "Your system is not supported (yet)"
	exit 2
fi
#Install cloak https://gist.github.com/cbeuw/37a9d434c237840d7e6d5e497539c1ca#file-shadowsocks-ck-release-sh-L118
url="https://github.com/cbeuw/Cloak/releases/download/v1.1.2/ck-server-linux-$arch-1.1.2"
urlc="https://github.com/cbeuw/Cloak/releases/download/v1.1.2/ck-client-linux-$arch-1.1.2"
#url=$(wget -O - -o /dev/null https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep "/ck-server-linux-$arch-" | grep -P 'https(.*)[^"]' -o)
wget -O ck-server "$url"
chmod +x ck-server
mv ck-server /usr/local/bin
#Install cloak client for post install management
#url=$(wget -O - -o /dev/null https://api.github.com/repos/cbeuw/Cloak/releases/latest | grep "/ck-client-linux-$arch-" | grep -P 'https(.*)[^"]' -o)
wget -O ck-client "$urlc"
chmod +x ck-client
mv ck-client /usr/local/bin
#Setup shadowsocks config
rm -f /etc/shadowsocks-libev/config.json
echo "{
    \"server\":\"0.0.0.0\",
    \"server_port\":$PORT,
    \"password\":\"$Password\",
    \"timeout\":60,
    \"method\":\"$cipher\",
    \"nameserver\":\"$dns\",
    \"plugin\":\"ck-server\",
    \"plugin_opts\":\"/etc/shadowsocks-libev/ckconfig.json\"
}" >>/etc/shadowsocks-libev/config.json
ckauid=$(ck-server -u) #https://gist.github.com/cbeuw/37a9d434c237840d7e6d5e497539c1ca#file-shadowsocks-ck-release-sh-L139
IFS=, read ckpub ckpv <<<$(ck-server -k)
echo "{
    \"WebServerAddr\":\"$ckwebaddr\",
    \"PrivateKey\":\"$ckpv\",
    \"AdminUID\":\"$ckauid\",
    \"DatabasePath\":\"/etc/shadowsocks-libev/userinfo.db\"
}" >>/etc/shadowsocks-libev/ckconfig.json
echo "{
	\"UID\":\"$ckauid\",
	\"PublicKey\":\"$ckpub\",
	\"ServerName\":\"$ckwebaddr\",
	\"TicketTimeHint\":3600,
	\"NumConn\":4,
	\"MaskBrowser\":\"chrome\"
}" >>/etc/shadowsocks-libev/ckclient.json
touch /etc/shadowsocks-libev/usersForScript.txt
chmod 777 /etc/shadowsocks-libev
#Service
rm /etc/systemd/system/shadowsocks-server.service
echo "[Unit]
Description=Shadowsocks-libev Server Service
Documentation=man:shadowsocks-libev(8)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
LimitNOFILE=32768
ExecStart=/usr/bin/ss-server
WorkingDirectory=/etc/shadowsocks-libev
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target" >>/etc/systemd/system/shadowsocks-server.service
systemctl daemon-reload
systemctl stop shadowsocks-libev
systemctl disable shadowsocks-libev
systemctl start shadowsocks-server
systemctl enable shadowsocks-server
#Show keys server and...
PUBLIC_IP="$(curl https://api.ipify.org -sS)"
CURL_EXIT_STATUS=$?
if [ $CURL_EXIT_STATUS -ne 0 ]; then
	PUBLIC_IP="YOUR_IP"
fi
clear
ShowConnectionInfo true
