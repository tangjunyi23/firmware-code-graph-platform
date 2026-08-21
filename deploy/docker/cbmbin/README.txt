放置说明：本目录是 docker-compose.yml 中 cbmbin 构建上下文的默认空占位。
要让镜像内置 codebase-memory-mcp（/cbmui 反代的上游），把本目录或 compose
中 build.additional_contexts.cbmbin 指向的目录里放入真实二进制——注意
~/.local/bin/codebase-memory-mcp 通常是符号链接，构建上下文不解引用外部
目标，请先拷贝实体：cp -L ~/.local/bin/codebase-memory-mcp <目录>/。
另注意二进制在部署机 glibc 下编译，与容器（debian slim）glibc 差距过大时
无法运行，入口脚本会打警告跳过并照常启动编排器。
