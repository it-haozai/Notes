```shell
xyz@xyz-Workstation:~$ docker run -d \
  --name prometheus \
  -p 9090:9090 \
  -v /usr/local/src/prometheus.yml:/etc/prometheus/prometheus.yml \
  --restart unless-stopped \
  prom/prometheus
```



```shell
xyz@xyz-Workstation:~$ sudo mkdir -p /usr/local/src/grafana-storage
xyz@xyz-Workstation:~$ sudo chmod 777 -R /usr/local/src/grafana-storage/
```



```shell
docker run -d \
  --name grafana \
  -p 3000:3000 \
  -v  /usr/local/src/grafana-storage:/var/lib/grafana \
  --restart unless-stopped \
  grafana/grafana
```

