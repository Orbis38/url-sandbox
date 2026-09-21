#!/bin/bash 

# Ensure standard binary paths are available under restrictive sudo environments
export PATH="/usr/local/bin:/usr/local/sbin:/usr/bin:/usr/sbin:/bin:/sbin:$PATH"

VERSION=$(jq -r '.version' info 2>/dev/null || grep -o '"version": *"[^"]*"' info 2>/dev/null | cut -d'"' -f4 || echo "latest")
echo -e "\nQeeqBox URL-Sandbox v${VERSION} starter script -> https://github.com/qeeqbox/url-sandbox"
echo -e "Open-Source URL Sandbox\n"

if [[ $EUID -ne 0 ]]; then
   echo -e "\nYou have to run this script with higher privileges\n" 
   exit 1
fi

compose_cmd () {
	if command -v docker-compose &> /dev/null; then
		docker-compose "$@"
	elif [ -x /usr/local/bin/docker-compose ]; then
		/usr/local/bin/docker-compose "$@"
	elif [ -x /usr/bin/docker-compose ]; then
		/usr/bin/docker-compose "$@"
	elif docker compose version &> /dev/null; then
		docker compose "$@"
	else
		echo "Error: docker-compose not found" >&2
		return 1
	fi
}

setup_requirements () {
	if [ -x "$(command -v apt)" ]; then
		apt update -y
		if ! command -v docker &> /dev/null
		then
				echo "Installing Docker"
				apt install -y linux-headers-$(uname -r) docker.io
		fi
		if ! command -v jq &> /dev/null
		then
				echo "Installing jq"
				apt install -y jq
		fi
		if ! command -v xdg-open &> /dev/null
		then
				echo "Installing xdg-utils"
				apt install -y xdg-utils
		fi
		if ! command -v curl &> /dev/null
		then
				echo "Installing curl"
				apt install -y curl
		fi
	elif [ -x "$(command -v dnf)" ]; then
		if ! command -v docker &> /dev/null
		then
				echo "Installing Docker (moby-engine)"
				dnf install -y kernel-devel moby-engine runc
		fi
		if ! command -v jq &> /dev/null
		then
				echo "Installing jq"
				dnf install -y jq
		fi
		if ! command -v xdg-open &> /dev/null
		then
				echo "Installing xdg-utils"
				dnf install -y xdg-utils
		fi
		if ! command -v curl &> /dev/null
		then
				echo "Installing curl"
				dnf install -y curl
		fi
	elif [ -x "$(command -v zypper)" ]; then
		zypper --non-interactive refresh
		if ! command -v docker &> /dev/null
		then
				echo "Installing Docker"
				zypper --non-interactive install -y docker
		fi
		if ! command -v jq &> /dev/null
		then
				echo "Installing jq"
				zypper --non-interactive install -y jq
		fi
		if ! command -v xdg-open &> /dev/null
		then
				echo "Installing xdg-utils"
				zypper --non-interactive install -y xdg-utils
		fi
		if ! command -v curl &> /dev/null
		then
				echo "Installing curl"
				zypper --non-interactive install -y curl
		fi
	else
		echo "Unsupported package manager. Please ensure docker, docker-compose, jq, and xdg-utils are installed."
	fi

	if ! command -v docker-compose &> /dev/null && [ ! -x /usr/local/bin/docker-compose ] && [ ! -x /usr/bin/docker-compose ]
	then
		if [ -x "$(command -v zypper)" ]; then
			zypper --non-interactive install -y docker-compose 2>/dev/null || true
		fi
		if ! command -v docker-compose &> /dev/null && [ ! -x /usr/local/bin/docker-compose ] && [ ! -x /usr/bin/docker-compose ]; then
			if docker compose version &> /dev/null
			then
				echo "Docker Compose v2 plugin detected, configuring docker-compose command"
				echo -e '#!/bin/sh\nexec docker compose "$@"' > /usr/local/bin/docker-compose
				chmod +x /usr/local/bin/docker-compose
			else
				echo "Installing docker-compose"
				curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
				chmod +x /usr/local/bin/docker-compose
			fi
		fi
	fi

	# Ensure docker-compose is available in both /usr/local/bin and /usr/bin for restrictive sudo PATH environments
	if [ -x /usr/local/bin/docker-compose ] && [ ! -e /usr/bin/docker-compose ]; then
		ln -sf /usr/local/bin/docker-compose /usr/bin/docker-compose 2>/dev/null || true
	elif [ -x /usr/bin/docker-compose ] && [ ! -e /usr/local/bin/docker-compose ]; then
		ln -sf /usr/bin/docker-compose /usr/local/bin/docker-compose 2>/dev/null || true
	fi

	ensure_docker
}

ensure_docker () {
	if docker info &> /dev/null; then
		return 0
	fi

	echo "Docker daemon is not running. Starting Docker service..."

	if command -v systemctl &> /dev/null; then
		systemctl unmask docker.service 2>/dev/null || true
		systemctl unmask docker.socket 2>/dev/null || true
		systemctl daemon-reload 2>/dev/null || true
		systemctl enable --now docker.socket 2>/dev/null || true
		systemctl enable --now docker 2>/dev/null || true
		systemctl start docker 2>/dev/null || true
	elif command -v service &> /dev/null; then
		service docker start 2>/dev/null || true
	else
		nohup dockerd > /var/log/dockerd.log 2>&1 &
	fi

	if [ ! -e /var/run/docker.sock ] && [ -e /run/docker.sock ]; then
		ln -sf /run/docker.sock /var/run/docker.sock 2>/dev/null || true
	fi

	if [ -n "$SUDO_USER" ] && getent group docker &>/dev/null; then
		usermod -aG docker "$SUDO_USER" 2>/dev/null || true
	fi

	local max_attempts=30
	local count=0
	echo -n "Waiting for Docker daemon to become ready"
	while ! docker info &> /dev/null; do
		sleep 1
		count=$((count + 1))
		echo -n "."
		if [ $count -ge $max_attempts ]; then
			echo -e "\nError: Docker daemon failed to start within ${max_attempts} seconds."
			if command -v journalctl &> /dev/null; then
				echo "Recent Docker service logs:"
				journalctl -u docker -n 25 --no-pager 2>/dev/null
			elif [ -f /var/log/dockerd.log ]; then
				echo "Recent Docker daemon logs (/var/log/dockerd.log):"
				tail -n 25 /var/log/dockerd.log
			fi
			exit 1
		fi
	done
	echo -e "\nDocker daemon is active and responsive."
}

wait_on_web_interface () {
	until curl --silent --head --fail http://127.0.0.1:8000 --output /dev/null; do
		sleep 5
	done
	xdg-open http://127.0.0.1:8000/url/ 2>/dev/null || true
}

test_project () {
	ensure_docker
	compose_cmd -f docker-compose-test.yml up --build
}

dev_project () {
	ensure_docker
	compose_cmd -f docker-compose-dev.yml up --build
}

stop_containers () {
	if ! docker info &>/dev/null; then
		return 0
	fi
	compose_cmd -f docker-compose-test.yml down -v 2>/dev/null || true
	compose_cmd -f docker-compose-dev.yml down -v 2>/dev/null || true
	local containers
	containers=$(docker ps -a -q --filter "name=url-sandbox_" 2>/dev/null)
	if [ -n "$containers" ]; then
		docker stop $containers 2>/dev/null || true
		docker rm -f $containers 2>/dev/null || true
	fi
} 

deploy_aws_project () {
	echo "Will be added later on"
}

auto_configure_test () {
	setup_requirements
	ensure_docker
	stop_containers
	wait_on_web_interface & 
	test_project
	stop_containers 
	kill %% 2>/dev/null
}

auto_configure () {
	setup_requirements
	ensure_docker
	stop_containers
	wait_on_web_interface & 
	dev_project
	stop_containers 
	kill %% 2>/dev/null
}

if [[ "$1" == "auto_test" ]]; then
	auto_configure_test
	exit 0
fi

if [[ "$1" == "auto_configure" ]]; then
	auto_configure
	exit 0
fi

kill %% 2>/dev/null

while read -p "`echo -e '\nChoose an option:\n1) Setup requirements (docker, docker-compose)\n2) Test the project (All servers and Sniffer)\n8) Run auto configuration\n9) Run auto test\n>> '`"; do
	case $REPLY in
		"1") setup_requirements;;
		"2") test_project;;
		"8") auto_configure;;
		"9") auto_configure_test;;
		*) echo "Invalid option";;
	esac
done
