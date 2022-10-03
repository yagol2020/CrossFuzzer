## 清空所有容器

```shell
docker rm $(docker ps -a -q)
```

## 暂停所有容器

```shell
docker stop $(docker ps -a -q)
```

## 进入容器

```shell
docker attach <container_id>
```

## SURYA

```shell
surya graph contracts/**/*.sol | dot -Tpng > MyContract.png
```