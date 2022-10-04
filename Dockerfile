FROM ubuntu:18.04

MAINTAINER Yagol (yhw_yagol@bistu.edu.cn)
SHELL ["/bin/bash", "-c"]
RUN apt-get update
RUN apt-get install -y sudo wget tar unzip pandoc python-setuptools python-pip python-dev python-virtualenv git build-essential software-properties-common python3-pip npm graphviz

# Install solidity
RUN wget https://github.com/ethereum/solidity/releases/download/v0.4.26/solc-static-linux && chmod +x solc-static-linux && mv solc-static-linux /usr/local/bin/solc
# Install z3
#RUN wget https://github.com/Z3Prover/z3/archive/Z3-4.8.5.zip && unzip Z3-4.8.5.zip && rm Z3-4.8.5.zip && cd z3-Z3-4.8.5 && python scripts/mk_make.py --python && cd build && make && sudo make install && cd ../.. && rm -r z3-Z3-4.8.5
# Install surya to analysis cross contract
RUN npm install -g surya
ENV LANG C.UTF-8
WORKDIR /root
COPY examples examples
COPY fuzzer fuzzer
RUN cd fuzzer && pip3 install --upgrade pip && pip3 install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
