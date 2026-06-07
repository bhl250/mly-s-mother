# 数据预处理项目迁移运行说明

这个项目用于处理 PCAP 数据，整体流程分两条线：

1. 预训练数据处理：从原始 PCAP/PCAPNG 生成 BURST 文本语料。
2. 微调数据处理：先把有标签 PCAP 按 packet 或 flow/session 切分，再生成训练、验证、测试数据。

迁移到新服务器时不要在源码里写死路径。下面所有路径都通过命令行参数传入。

本文档里“必填”表示必须通过命令行参数传入，或者用对应环境变量提供。推荐优先使用命令行参数，因为命令本身就能记录本次运行使用的数据路径。

## 1. 服务器初始化

在新服务器拉取项目后，先进入项目根目录。

安装外部命令行依赖：

```bash
bash scripts/install_cli_deps.sh
```

这个脚本会安装并注册这些外部工具：

- `editcap`
- `tshark`
- `mergecap`

同时也会安装创建项目虚拟环境需要的系统包：

- `python3-venv`
- `python3-pip`

它们来自 Ubuntu/Debian 的 Wireshark 命令行包，不是 Windows `.exe`。脚本会把系统命令软链接到项目目录：

```bash
bin/editcap
bin/tshark
bin/mergecap
```

并生成：

```bash
env.sh
```

当前 shell 立即生效：

```bash
source env.sh
```

如果服务器不允许写 `/etc/profile.d`，用这个命令安装：

```bash
REGISTER_SYSTEM_PATH=0 bash scripts/install_cli_deps.sh
source env.sh
```

创建项目内 Python 虚拟环境并安装 Python 依赖：

```bash
bash scripts/setup_python_env.sh
```

如果这里报 `ensurepip is not available`，说明服务器缺 Python venv 系统包。先执行：

```bash
bash scripts/install_cli_deps.sh
```

或者手动安装：

```bash
apt-get update
apt-get install -y python3-venv python3-pip
```

如果服务器提示类似 `apt install python3.10-venv`，就安装它提示的版本包：

```bash
apt-get install -y python3.10-venv
```

这个脚本会在项目根目录创建：

```bash
.venv/
```

并生成本机专用激活脚本：

```bash
activate_project_env.sh
```

激活项目环境：

```bash
source activate_project_env.sh
```

检查外部命令：

```bash
which editcap
which tshark
which mergecap
editcap --version
tshark --version
mergecap --version
```

检查 Python 环境：

```bash
python -c "import numpy, pandas, scipy, sklearn, tqdm, xlrd, scapy, flowcontainer; print('python deps ok')"
python -c "from pcap_splitter.splitter import PcapSplitter; print('pcap_splitter ok')"
```

## 2. 日志文件

数据处理脚本会同时把进度输出到终端和日志文件。默认日志目录是：

```bash
logs/
```

不同阶段的默认日志文件：

| 阶段 | 默认日志文件 | 说明 |
| --- | --- | --- |
| 预训练数据处理 | `logs/pretrain.log` | 记录原始 pcap 数量、pcapng 转换数量、切分数量、BURST 特征生成数量和最终语料路径。 |
| 微调 PCAP 切分 | `logs/finetune_split.log` | 记录标签数量、每个标签下 pcap 数量、已切分文件数、pcapng 转换数量和 splitcap 输出路径。 |
| 微调数据集生成 | `logs/finetune_generate.log` | 记录输入 splitcap 路径、样本参数、类别统计、train/valid/test 数量、`.npy` 和 `.tsv` 输出路径。 |

实时查看日志：

```bash
tail -f logs/pretrain.log
tail -f logs/finetune_split.log
tail -f logs/finetune_generate.log
```

如果你想把日志写到指定路径，可以传 `--log-file`：

```bash
python data_process/dataset_generation.py pretrain \
  --pcap-path /data/pretrain/raw_pcaps \
  --log-file /data/logs/pretrain_run_001.log
```

```bash
python data_process/dataset_generation.py split-finetune \
  --pcap-path /data/finetune/raw_pcaps \
  --dataset-level packet \
  --log-file /data/logs/finetune_split_run_001.log
```

```bash
python data_process/main.py \
  --pcap-path /data/finetune/raw_pcaps/splitcap \
  --log-file /data/logs/finetune_generate_run_001.log
```

日志级别默认是 `INFO`。需要更详细日志时可以传：

```bash
--log-level DEBUG
```

## 3. Python 依赖

必须依赖写在：

```bash
requirements.txt
```

当前包括：

- `numpy`
- `pandas`
- `scipy`
- `scikit-learn`
- `tqdm`
- `xlrd`
- `scapy`
- `flowcontainer`

可选依赖写在：

```bash
requirements-optional.txt
```

当前包括：

- `pcap-splitter`

说明：`pcap-splitter` 是可选加速/兼容依赖。它内部还会尝试调用 `PcapSplitter` 二进制；如果不可用，代码会自动 fallback 到 Scapy 做切分。

## 4. 预训练数据处理

主脚本：

```bash
data_process/dataset_generation.py
```

子命令：

```bash
pretrain
```

输入数据建议结构：

```text
/data/pretrain/raw_pcaps/
  a.pcap
  b.pcapng
  subdir/
    c.pcap
```

运行命令示例：

```bash
python data_process/dataset_generation.py pretrain \
  --pcap-path /data/pretrain/raw_pcaps \
  --output-split-path /data/pretrain/work \
  --pcap-output-path /data/pretrain/work/pcap \
  --word-dir /data/pretrain/corpora \
  --word-name encrypted_burst.txt \
  --payload-len 64
```

参数说明：

| 参数 | 是否必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--pcap-path` | 必填 | 可用环境变量 `PCAP_PATH` 提供 | 原始 PCAP/PCAPNG 输入目录。这个是输入数据路径，服务器迁移后必须明确指定。 |
| `--output-split-path` | 可选 | 环境变量 `OUTPUT_SPLIT_PATH`，否则 `./dataset` | 预训练中间切分结果目录。脚本会在下面生成 `splitcap/`。 |
| `--pcap-output-path` | 可选 | 环境变量 `PCAP_OUTPUT_PATH`，否则 `--output-split-path/pcap` | 标准化后的 `.pcap` 存放目录。遇到 `.pcapng` 会用 `editcap` 转成 `.pcap`。 |
| `--word-dir` | 可选 | 环境变量 `WORD_DIR`，否则 `./corpora` | 最终预训练 BURST 文本语料输出目录。 |
| `--word-name` | 可选 | 环境变量 `WORD_NAME`，否则 `encrypted_burst.txt` | 最终预训练 BURST 文本语料文件名。 |
| `--payload-len` | 可选 | `64` | 提取 BURST 特征时截取的 payload 长度。 |

最小命令只需要传输入数据路径：

```bash
python data_process/dataset_generation.py pretrain \
  --pcap-path /data/pretrain/raw_pcaps
```

这会使用默认输出目录：

```text
./dataset/
./dataset/pcap/
./corpora/encrypted_burst.txt
```

主要输出：

```text
/data/pretrain/work/pcap/
  *.pcap

/data/pretrain/work/splitcap/
  ...

/data/pretrain/corpora/encrypted_burst.txt
```

查看预训练命令帮助：

```bash
python data_process/dataset_generation.py pretrain --help
```

## 5. 微调数据处理

微调数据分两步：

1. 先把有标签 PCAP 切成 packet 或 flow/session 样本。
2. 再从切分后的样本生成 `dataset.json`、`.npy`、`.tsv`。

### 5.1 微调数据输入目录结构

原始有标签 PCAP 建议按类别目录组织：

```text
/data/finetune/raw_pcaps/
  label_0/
    a.pcap
    b.pcapng
  label_1/
    c.pcap
  label_2/
    d.pcap
```

目录名就是类别名。脚本会根据这些类别目录建立 label id。

### 5.2 第一步：切分微调 PCAP

主脚本：

```bash
data_process/dataset_generation.py
```

子命令：

```bash
split-finetune
```

按 packet 切分：

```bash
python data_process/dataset_generation.py split-finetune \
  --pcap-path /data/finetune/raw_pcaps \
  --dataset-level packet
```

按 flow/session 切分：

```bash
python data_process/dataset_generation.py split-finetune \
  --pcap-path /data/finetune/raw_pcaps \
  --dataset-level flow
```

参数说明：

| 参数 | 是否必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--pcap-path` | 必填 | 可用环境变量 `PCAP_PATH` 提供 | 原始有标签 PCAP 根目录，要求结构是 `PCAP_PATH/<label>/*.pcap`。这是输入数据路径，必须明确指定。 |
| `--dataset-level` | 可选 | `packet` | `packet` 表示每个切分样本是一包；`flow` 表示每个切分样本是一个 session/flow。 |

最小命令：

```bash
python data_process/dataset_generation.py split-finetune \
  --pcap-path /data/finetune/raw_pcaps
```

不传 `--dataset-level` 时默认按 `packet` 切分。

主要输出：

```text
/data/finetune/raw_pcaps/splitcap/
  label_0/
    original_file_1/
      *.pcap
  label_1/
    original_file_2/
      *.pcap
```

如果输入里有 `.pcapng`，脚本会先用 `editcap` 转成 `.pcap`，中间文件输出到：

```text
/data/finetune/raw_pcaps/converted_pcap/
```

查看切分命令帮助：

```bash
python data_process/dataset_generation.py split-finetune --help
```

### 5.3 第二步：生成微调训练数据

主脚本：

```bash
data_process/main.py
```

典型 packet 级微调数据生成命令：

```bash
python data_process/main.py \
  --pcap-path /data/finetune/raw_pcaps/splitcap \
  --dataset-save-path /data/finetune/result \
  --dataset-dir /data/finetune/datasets \
  --samples 5000 \
  --category 120 \
  --dataset-level packet \
  --features payload \
  --models pre-train
```

典型 flow/session 级微调数据生成命令：

```bash
python data_process/main.py \
  --pcap-path /data/finetune/raw_pcaps/splitcap \
  --dataset-save-path /data/finetune/result_flow \
  --dataset-dir /data/finetune/datasets_flow \
  --samples 5000 \
  --category 120 \
  --dataset-level flow \
  --features payload \
  --models pre-train
```

参数说明：

| 参数 | 是否必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `--pcap-path` | 必填 | 可用环境变量 `PCAP_PATH` 提供 | 切分后的 PCAP 根目录，一般是上一步生成的 `.../splitcap`。这是输入数据路径，必须明确指定。 |
| `--dataset-save-path` | 可选 | 环境变量 `DATASET_SAVE_PATH`，否则 `./finetune_result` | 保存 `dataset.json`、`picked_file_record` 和 `.npy` 缓存的目录。 |
| `--dataset-dir` | 可选 | 环境变量 `DATASET_DIR`，否则 `./datasets` | 保存最终 TSV 文件的目录。 |
| `--samples` | 可选 | `5000` | 每个类别抽样数量。 |
| `--category` | 可选 | `120` | 类别总数。 |
| `--dataset-level` | 可选 | `packet` | 必须和上一步切分方式一致，取值是 `packet` 或 `flow`。 |
| `--features` | 可选 | `payload` | 特征类型，当前主流程通常使用 `payload`。 |
| `--models` | 可选 | `pre-train` | 输出模型模式，当前用于生成 TSV 的模式是 `pre-train`。 |
| `--splitcap-finish` | 可选 | 默认不开启 | 开启后会统计已有切分样本数量，并把抽样数限制到实际可用数量。 |
| `--open-dataset-not-pcap` | 可选 | 默认不开启 | 对非标准 pcap/open dataset 文件先调用 `tshark` 转 pcap。 |
| `--file2dir` | 可选 | 默认不开启 | 当每个 pcap 文件本身代表一个类别时，把文件移动到同名类别目录。 |

最小命令：

```bash
python data_process/main.py \
  --pcap-path /data/finetune/raw_pcaps/splitcap
```

这会使用默认输出：

```text
./finetune_result/
./datasets/
```

`--samples` 的传法：

所有类别同样抽样数：

```bash
--samples 5000
```

每个类别不同抽样数时，传逗号分隔列表，数量必须等于 `--category`：

```bash
--samples 1000,1200,900,1500
```

如果想根据实际已有文件数自动把抽样数限制到可用数量，加：

```bash
--splitcap-finish
```

示例：

```bash
python data_process/main.py \
  --pcap-path /data/finetune/raw_pcaps/splitcap \
  --dataset-save-path /data/finetune/result \
  --dataset-dir /data/finetune/datasets \
  --samples 5000 \
  --category 120 \
  --dataset-level packet \
  --features payload \
  --models pre-train \
  --splitcap-finish
```

主要输出：

```text
/data/finetune/result/
  dataset.json
  picked_file_record
  dataset/
    x_datagram_train.npy
    x_datagram_test.npy
    x_datagram_valid.npy
    y_train.npy
    y_test.npy
    y_valid.npy

/data/finetune/datasets/
  train_dataset.tsv
  test_dataset.tsv
  valid_dataset.tsv
  nolabel_test_dataset.tsv
```

查看微调生成命令帮助：

```bash
python data_process/main.py --help
```

## 6. 推荐完整服务器运行流程

假设服务器上的数据路径如下：

```text
/data/pretrain/raw_pcaps
/data/finetune/raw_pcaps
```

完整流程：

```bash
# 1. 安装外部命令
bash scripts/install_cli_deps.sh
source env.sh

# 2. 创建项目 venv 并激活
bash scripts/setup_python_env.sh
source activate_project_env.sh

# 3. 处理预训练数据
python data_process/dataset_generation.py pretrain \
  --pcap-path /data/pretrain/raw_pcaps \
  --output-split-path /data/pretrain/work \
  --pcap-output-path /data/pretrain/work/pcap \
  --word-dir /data/pretrain/corpora \
  --word-name encrypted_burst.txt \
  --payload-len 64 \
  --log-file /data/logs/pretrain.log

# 4. 切分微调数据
python data_process/dataset_generation.py split-finetune \
  --pcap-path /data/finetune/raw_pcaps \
  --dataset-level packet \
  --log-file /data/logs/finetune_split.log

# 5. 生成微调数据集
python data_process/main.py \
  --pcap-path /data/finetune/raw_pcaps/splitcap \
  --dataset-save-path /data/finetune/result \
  --dataset-dir /data/finetune/datasets \
  --samples 5000 \
  --category 120 \
  --dataset-level packet \
  --features payload \
  --models pre-train \
  --log-file /data/logs/finetune_generate.log
```

## 7. 不要写死路径

不要再改源码里的路径。迁移到不同服务器时，只改命令行参数：

- `--pcap-path`
- `--output-split-path`
- `--pcap-output-path`
- `--word-dir`
- `--word-name`
- `--dataset-save-path`
- `--dataset-dir`

如果必须用环境变量，也支持这些变量：

- `PCAP_PATH`
- `OUTPUT_SPLIT_PATH`
- `PCAP_OUTPUT_PATH`
- `WORD_DIR`
- `WORD_NAME`
- `DATASET_SAVE_PATH`
- `DATASET_DIR`

但推荐优先使用命令行参数，因为命令更清楚、可记录、可复现。

必须明确提供的输入路径：

- 预训练阶段的 `data_process/dataset_generation.py pretrain --pcap-path`
- 微调切分阶段的 `data_process/dataset_generation.py split-finetune --pcap-path`
- 微调生成阶段的 `data_process/main.py --pcap-path`

这些参数如果不通过命令行传，就必须提前设置 `PCAP_PATH`。除此之外的输出目录和处理参数都有默认值。

## 8. Git 追踪规则

应该追踪源码、安装脚本、依赖清单和迁移说明：

```bash
git add .gitignore \
  README2.md \
  requirements.txt \
  requirements-optional.txt \
  scripts/setup_python_env.sh \
  scripts/install_cli_deps.sh \
  data_process/README.md \
  data_process/data_preprocess.py \
  data_process/dataset_cleanning.py \
  data_process/dataset_generation.py \
  data_process/main.py \
  data_process/open_dataset_deal.py
```

不要追踪本地运行产物：

- `.venv/`
- `activate_project_env.sh`
- `env.sh`
- `bin/`
- `logs/`
- `__pycache__/`
- `*.pyc`
- `dataset/`
- `datasets/`
- `pcaps/`
- `corpora/`
- `ex_results/`
- `traffic_pcap/`
- `cstnet-tls1.3/`

`activate_project_env.sh` 和 `env.sh` 里面有当前机器的绝对路径。每台服务器都应该通过下面命令重新生成：

```bash
bash scripts/setup_python_env.sh
bash scripts/install_cli_deps.sh
```
