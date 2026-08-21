放置说明：本目录是 docker-compose.yml 中 ida 构建上下文的默认空占位。
部署机装有 IDA Pro 时，把 compose 里 build.additional_contexts.ida 指向
真实安装目录（含 idat 的目录，如 /opt/ida-pro-9.1），镜像才会内置 IDA；
缺省构建的镜像 /opt/ida 仅含本文件，反编译相关接口不可用。
命令行直接构建时等价参数：--build-context ida=<IDA 安装目录>。
