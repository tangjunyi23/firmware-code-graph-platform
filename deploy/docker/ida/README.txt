放置说明：本目录是 docker-compose.yml 中 ida 构建上下文的默认空占位。
ELF 反编译已内置仓库里的 rootfs_elf（rootfs_elf.tar.gz，无 Hex-Rays 许可文件），
不必在这里放 IDA。
仅当需要 raw/PX4 的 idat 导出时，才把 additional_contexts.ida 指向含 idat
的安装目录。命令行：--build-context ida=<IDA 安装目录>。
