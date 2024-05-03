FROM ubuntu:20.04

USER root

RUN apt update -y
RUN apt install git curl vim \
  python3 python3-pip python3-venv \
  python3-distutils python3-dev gcc -y
  
RUN git config --global credential.helper store

RUN mkdir -p /home/root
WORKDIR /home/root

VOLUME [ "/home/root" ]
