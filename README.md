# socks5 

### Quick Start

#### Build the project

```bash
cd ./cmd/server/
GOOS=linux GOARCH=amd64 go build main.go
```

#### SFTP to the server

```bash
sftp root@proxy
> put ./main .
```

#### Run in it

```bash
nohup ./main > output &
```

#### **Get the token use http**

```bash
# first get the token
head -n 1 output
# then curl the server
curl 'http://${server_ip}/?token=${ur token}' \
  -H 'Pragma: no-cache' \
  -H 'Cache-Control: no-cache' \
  -H 'Upgrade-Insecure-Requests: 1' \
  --compressed \
  --insecure
```

