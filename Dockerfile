FROM ubuntu:jammy

LABEL org.opencontainers.image.authors=christof.torres@uni.lu

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get -y update \
  && apt-get install -y \
    python-is-python3 python3 python3-pip python3-virtualenv python3-dev \
    build-essential git \
    python3-pip wget \
    psmisc lsof time \
    wget tar unzip pandoc \
  && apt-get clean -y \
  && rm -rf /var/lib/apt/lists/*

ARG Z3_VERSION=4.8.5
RUN pip3 install z3-solver==$Z3_VERSION

WORKDIR /root
COPY examples examples
COPY fuzzer fuzzer
RUN cd fuzzer && pip3 install -r requirements.txt

ARG SOLCX_BIN_PATH=/root/.solcx/
RUN python -c 'import solcx; print(list(map(solcx.install_solc, ["0.7.6", "0.5.6", "0.4.26", "0.4.23"])));' \
  && test -d $SOLCX_BIN_PATH \
  && ln -s $SOLCX_BIN_PATH/solc-v0.7.6 /usr/local/solc

ENV PATH=$PATH:$SOLCX_BIN_PATH

# some dirty patching for py3.10 compat...
RUN sed -i 's/from collections /from collections.abc /g' \
  /usr/local/lib/python3.10/dist-packages/eth_account/account.py \
  /usr/local/lib/python3.10/dist-packages/attrdict/mapping.py \
  /usr/local/lib/python3.10/dist-packages/attrdict/mixins.py \
  /usr/local/lib/python3.10/dist-packages/attrdict/merge.py \
  /usr/local/lib/python3.10/dist-packages/attrdict/default.py \
  /usr/local/lib/python3.10/dist-packages/web3/utils/formatters.py 

RUN cd /usr/local/lib/python3.10/dist-packages/web3/ \
  && cp datastructures.py datastructures.py.bak \
  && echo "from collections.abc import Hashable, Mapping, MutableMapping, Sequence" > datastructures.py \
  && echo "from collections import OrderedDict" >> datastructures.py \
  && tail -n '+8' datastructures.py.bak >> datastructures.py

RUN sed -i 's/collections.Generator/collections.abc.Generator/g' \
  /usr/local/lib/python3.10/dist-packages/web3/utils/six/six.py

# sanity check
RUN cd fuzzer && python3 main.py --help >/dev/null
