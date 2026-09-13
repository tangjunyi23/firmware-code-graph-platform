把你的 IDA 安装整目录拷到这里，平台会自动识别，不必改镜像、不必设 IDA_DIR。

推荐布局（任选一种）：

  deploy/docker/ida-drop/idat          ← 安装根就在这一层
  deploy/docker/ida-drop/ida-pro-9.1/idat
  deploy/docker/ida-drop/ida-pro-9.1/libidalib.so

识别到 idat、idat64 或 libidalib.so 即视为可用。
改完文件后重启编排器：

  docker compose -f deploy/docker/docker-compose.yml restart orchestrator

容器内对应路径是 /opt/ida-drop。也可以把 IDA 放到数据盘 data/ida/。
